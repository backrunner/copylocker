use copylocker_server_core::policy::Validity;
use copylocker_server_core::{Subscription, SubscriptionEvent, SubscriptionState};
use copylocker_suite::Secret;
use copylocker_types::VersionScope;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use worker::wasm_bindgen::JsValue;
use worker::{
    D1Database, D1SessionConstraint, D1Type, Date, Env, Method, Request, Response, Result,
};
use zeroize::Zeroize;

use crate::middleware::body::{self, BodyError};
use crate::response;

const MAX_WEBHOOK_BODY: usize = 64 * 1024;
const SIGNATURE_TOLERANCE_SECS: i64 = 5 * 60;
const REFUND_REVIEW_SECS: i64 = 7 * 86_400;
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
pub(crate) const BILLING_WEBHOOK_EVENT: &str = "billing_webhook";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BillingProvider {
    Stripe,
    Paddle,
    LemonSqueezy,
}

impl BillingProvider {
    pub(crate) fn parse_path(path: &str) -> Option<Self> {
        match path {
            "/webhooks/stripe" => Some(Self::Stripe),
            "/webhooks/paddle" => Some(Self::Paddle),
            "/webhooks/lemonsqueezy" => Some(Self::LemonSqueezy),
            _ => None,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Stripe => "stripe",
            Self::Paddle => "paddle",
            Self::LemonSqueezy => "lemonsqueezy",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "stripe" => Some(Self::Stripe),
            "paddle" => Some(Self::Paddle),
            "lemonsqueezy" => Some(Self::LemonSqueezy),
            _ => None,
        }
    }

    const fn production_secret_binding(self) -> &'static str {
        match self {
            Self::Stripe => "STRIPE_WEBHOOK_SECRET",
            Self::Paddle => "PADDLE_WEBHOOK_SECRET",
            Self::LemonSqueezy => "LEMONSQUEEZY_WEBHOOK_SECRET",
        }
    }

    const fn test_secret_binding(self) -> &'static str {
        match self {
            Self::Stripe => "TEST_STRIPE_WEBHOOK_SECRET",
            Self::Paddle => "TEST_PADDLE_WEBHOOK_SECRET",
            Self::LemonSqueezy => "TEST_LEMONSQUEEZY_WEBHOOK_SECRET",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum BillingEventKind {
    Started {
        license_id: Vec<u8>,
        period_start: i64,
        period_end: i64,
        billing_period: String,
    },
    Renewed {
        period_start: i64,
        period_end: i64,
    },
    PaymentFailed,
    DunningLapsed,
    PaymentRecovered,
    CancelAtPeriodEnd,
    PeriodEnded,
    RefundReported,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BillingWebhookEvent {
    event: String,
    schema_version: u8,
    provider: BillingProvider,
    event_id: String,
    event_ts: i64,
    external_id: String,
    event_kind: BillingEventKind,
}

impl BillingWebhookEvent {
    pub(crate) fn is_valid(&self) -> bool {
        self.event == BILLING_WEBHOOK_EVENT
            && self.schema_version == 1
            && valid_identifier(&self.event_id, 200)
            && valid_identifier(&self.external_id, 200)
            && (0..=MAX_SAFE_INTEGER).contains(&self.event_ts)
            && match &self.event_kind {
                BillingEventKind::Started {
                    license_id,
                    period_start,
                    period_end,
                    billing_period,
                } => {
                    license_id.len() == 16
                        && valid_period(*period_start, *period_end)
                        && valid_identifier(billing_period, 32)
                }
                BillingEventKind::Renewed {
                    period_start,
                    period_end,
                } => valid_period(*period_start, *period_end),
                _ => true,
            }
    }
}

pub(crate) async fn route(
    request: &mut Request,
    env: &Env,
    provider: BillingProvider,
) -> Result<Response> {
    if request.method() != Method::Post {
        return response::api_error_no_store(405, "method_not_allowed", "HTTP method not allowed");
    }
    if !is_json_request(request)? {
        return response::api_error_no_store(
            415,
            "unsupported_media_type",
            "Content-Type must be application/json and Content-Encoding must be identity",
        );
    }
    let bytes = match body::read_raw(request, MAX_WEBHOOK_BODY).await {
        Ok(bytes) => bytes,
        Err(BodyError::TooLarge | BodyError::InvalidContentLength) => {
            return response::api_error_no_store(
                413,
                "payload_too_large",
                "webhook body exceeds the 65536-byte limit",
            );
        }
        Err(_) => {
            return response::api_error_no_store(
                400,
                "invalid_request",
                "webhook body could not be read",
            );
        }
    };
    let secret = load_secret(env, provider).await?;
    if !verify_request_signature(request, provider, secret.expose().as_bytes(), &bytes)? {
        return response::api_error_no_store(
            401,
            "invalid_signature",
            "webhook signature is invalid",
        );
    }
    let value: Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => {
            return response::api_error_no_store(
                400,
                "invalid_payload",
                "webhook payload is not valid JSON",
            );
        }
    };
    let event = match normalize(provider, &value) {
        Ok(Some(event)) if event.is_valid() => event,
        Ok(None) => {
            return response::json_no_store(
                200,
                &serde_json::json!({ "ok": true, "accepted": false, "ignored": true }),
            );
        }
        _ => {
            return response::api_error_no_store(
                400,
                "invalid_payload",
                "webhook payload is missing required subscription fields",
            );
        }
    };

    env.queue("EVENTS")?.send(event).await?;
    response::json_no_store(202, &serde_json::json!({ "ok": true, "accepted": true }))
}

pub(crate) async fn process(env: &Env, event: &BillingWebhookEvent) -> Result<()> {
    if !event.is_valid() {
        return Err(worker::Error::RustError(
            "billing webhook event failed validation".into(),
        ));
    }
    let database = env.d1("DB")?;
    if billing_event_exists(&database, event).await? {
        return Ok(());
    }
    match &event.event_kind {
        BillingEventKind::Started {
            license_id,
            period_start,
            period_end,
            billing_period,
        } => {
            process_started(
                &database,
                event,
                license_id,
                *period_start,
                *period_end,
                billing_period,
            )
            .await
        }
        kind => process_existing(&database, event, kind).await,
    }
}

pub(crate) async fn reconcile_due(env: &Env) -> Result<usize> {
    let now = now_seconds();
    let database = env.d1("DB")?;
    let due = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(
            "SELECT license_id, provider, external_id, state, current_period_end, \
                    dunning_until, refund_observe_until \
             FROM subscriptions \
             WHERE (refund_observe_until IS NOT NULL AND refund_observe_until <= ?1) \
                OR (state = 'past_due' AND dunning_until IS NOT NULL AND dunning_until <= ?1) \
                OR (state = 'canceling' AND current_period_end <= ?1) \
             ORDER BY COALESCE(refund_observe_until, dunning_until, current_period_end) \
             LIMIT 100",
        )
        .bind(&[integer(now)?])?
        .all()
        .await?
        .results::<DueSubscriptionRow>()?;
    let mut reconciled = 0usize;
    for row in due {
        if let Some(review_until) = row.refund_observe_until.filter(|until| *until <= now) {
            let request_id = format!(
                "billing-refund:{}:{review_until}",
                hex_encode(&row.license_id)
            );
            crate::admin::revoke_refunded_license(env, &row.license_id, &request_id).await?;
            database
                .prepare(
                    "UPDATE subscriptions SET state = 'expired', fallback_earned_at = NULL, \
                       refund_observe_until = NULL, updated_at = ? \
                     WHERE license_id = ? AND refund_observe_until = ?",
                )
                .bind(&[integer(now)?, blob(&row.license_id), integer(review_until)?])?
                .run()
                .await?;
            reconciled = reconciled.saturating_add(1);
            continue;
        }

        let provider = BillingProvider::from_str(&row.provider).ok_or_else(|| {
            worker::Error::RustError("subscription has an invalid billing provider".into())
        })?;
        let (due_at, event_kind, label) = match row.state.as_str() {
            "past_due" => (
                row.dunning_until.ok_or_else(|| {
                    worker::Error::RustError("past-due subscription has no deadline".into())
                })?,
                BillingEventKind::DunningLapsed,
                "dunning",
            ),
            "canceling" => (
                row.current_period_end,
                BillingEventKind::PeriodEnded,
                "period-end",
            ),
            _ => continue,
        };
        let event = new_event(
            provider,
            &format!("system:{label}:{}:{due_at}", hex_encode(&row.license_id)),
            due_at,
            &row.external_id,
            event_kind,
        );
        process(env, &event).await?;
        reconciled = reconciled.saturating_add(1);
    }
    Ok(reconciled)
}

async fn process_started(
    database: &D1Database,
    event: &BillingWebhookEvent,
    license_id: &[u8],
    period_start: i64,
    period_end: i64,
    billing_period: &str,
) -> Result<()> {
    let license = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(
            "SELECT p.validity_json FROM licenses l \
             JOIN policies p ON p.id = l.policy_id WHERE l.id = ?",
        )
        .bind(&[blob(license_id)])?
        .first::<LicensePolicyRow>(None)
        .await?
        .ok_or_else(|| worker::Error::RustError("billing license does not exist".into()))?;
    let (dunning_secs, _) = subscription_terms(&license.validity_json)?;
    let subscription = Subscription::new(
        event.provider.as_str(),
        &event.external_id,
        period_start,
        period_end,
    );
    let expiry = period_end.saturating_add(dunning_secs);
    let statements = vec![
        database
            .prepare(
                "INSERT INTO subscriptions(\
                   license_id, provider, external_id, state, billing_period, \
                   current_period_start, current_period_end, dunning_until, \
                   continuous_paid_months, fallback_earned_at, canceled_at, updated_at, \
                   refund_observe_until\
                 ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 0, NULL, NULL, ?, NULL)",
            )
            .bind(&[
                blob(license_id),
                text(event.provider.as_str()),
                text(&event.external_id),
                text(state_name(subscription.state)),
                text(billing_period),
                integer(period_start)?,
                integer(period_end)?,
                integer(event.event_ts)?,
            ])?,
        database
            .prepare("UPDATE licenses SET status = 'active', expires_at = ?, updated_at = ? WHERE id = ?")
            .bind(&[
                integer(expiry)?,
                integer(event.event_ts)?,
                blob(license_id),
            ])?,
        billing_event_statement(database, event)?,
    ];
    database.batch(statements).await?;
    Ok(())
}

async fn process_existing(
    database: &D1Database,
    event: &BillingWebhookEvent,
    kind: &BillingEventKind,
) -> Result<()> {
    let row = database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(
            "SELECT s.license_id, s.provider, s.external_id, s.state, s.current_period_start, \
                    s.current_period_end, s.dunning_until, s.continuous_paid_months, \
                    s.fallback_earned_at, s.canceled_at, s.updated_at, \
                    s.refund_observe_until, p.validity_json \
             FROM subscriptions s \
             JOIN licenses l ON l.id = s.license_id \
             JOIN policies p ON p.id = l.policy_id \
             WHERE s.provider = ? AND s.external_id = ?",
        )
        .bind(&[text(event.provider.as_str()), text(&event.external_id)])?
        .first::<SubscriptionRow>(None)
        .await?
        .ok_or_else(|| worker::Error::RustError("billing subscription does not exist".into()))?;
    let (dunning_secs, fallback) = subscription_terms(&row.validity_json)?;
    let mut subscription = row.to_subscription()?;
    let subscription_event = match kind {
        BillingEventKind::Renewed {
            period_start,
            period_end,
        } => SubscriptionEvent::Renewed {
            period_start: *period_start,
            period_end: *period_end,
        },
        BillingEventKind::PaymentFailed => SubscriptionEvent::PaymentFailed,
        BillingEventKind::DunningLapsed => SubscriptionEvent::DunningElapsed,
        BillingEventKind::PaymentRecovered => SubscriptionEvent::PaymentRecovered,
        BillingEventKind::CancelAtPeriodEnd => SubscriptionEvent::CancelAtPeriodEnd,
        BillingEventKind::PeriodEnded => SubscriptionEvent::PeriodElapsed,
        BillingEventKind::RefundReported => SubscriptionEvent::RefundReported,
        BillingEventKind::Started { .. } => {
            return Err(worker::Error::RustError(
                "started event reached existing subscription path".into(),
            ));
        }
    };
    subscription.apply(
        &event.event_id,
        &subscription_event,
        fallback,
        event.event_ts,
        dunning_secs,
    );
    let refund_observe_until = if matches!(kind, BillingEventKind::RefundReported) {
        Some(event.event_ts.saturating_add(REFUND_REVIEW_SECS))
    } else {
        row.refund_observe_until
    };
    let license_update = license_update(
        database,
        &row.license_id,
        kind,
        &subscription,
        fallback,
        dunning_secs,
    )?;
    let statements = vec![
        database
            .prepare(
                "UPDATE subscriptions SET state = ?, current_period_start = ?, \
                   current_period_end = ?, dunning_until = ?, continuous_paid_months = ?, \
                   fallback_earned_at = ?, canceled_at = ?, updated_at = ?, \
                   refund_observe_until = ? WHERE license_id = ?",
            )
            .bind(&[
                text(state_name(subscription.state)),
                integer(subscription.current_period_start)?,
                integer(subscription.current_period_end)?,
                optional_integer(subscription.dunning_until)?,
                integer(i64::from(subscription.continuous_paid_months))?,
                optional_integer(subscription.fallback_earned_at)?,
                optional_integer(subscription.canceled_at)?,
                integer(subscription.updated_at)?,
                optional_integer(refund_observe_until)?,
                blob(&row.license_id),
            ])?,
        license_update,
        billing_event_statement(database, event)?,
    ];
    database.batch(statements).await?;
    Ok(())
}

fn license_update(
    database: &D1Database,
    license_id: &[u8],
    kind: &BillingEventKind,
    subscription: &Subscription,
    fallback: Option<copylocker_server_core::policy::PerpetualFallback>,
    dunning_secs: i64,
) -> Result<worker::D1PreparedStatement> {
    let (status, expiry, version_scope) = match subscription.state {
        SubscriptionState::Suspended => ("suspended", None, None),
        SubscriptionState::Expired | SubscriptionState::Ended => ("expired", None, None),
        SubscriptionState::PerpetualFallback => {
            let scope = subscription
                .fallback_version_cutoff(fallback)
                .map(VersionScope::ReleasedBefore)
                .map(|scope| serde_json::to_string(&scope))
                .transpose()
                .map_err(|_| worker::Error::RustError("fallback scope encoding failed".into()))?;
            ("active", None, scope)
        }
        _ => {
            let expiry = if matches!(kind, BillingEventKind::Renewed { .. }) {
                Some(subscription.current_period_end.saturating_add(dunning_secs))
            } else {
                None
            };
            ("active", expiry, None)
        }
    };
    database
        .prepare(
            "UPDATE licenses SET status = ?, \
               expires_at = CASE WHEN ? IS NULL THEN expires_at ELSE ? END, \
               version_scope_override_json = COALESCE(?, version_scope_override_json), \
               updated_at = ? WHERE id = ?",
        )
        .bind(&[
            text(status),
            optional_integer(expiry)?,
            optional_integer(expiry)?,
            optional_text(version_scope.as_deref()),
            integer(subscription.updated_at)?,
            blob(license_id),
        ])
}

async fn billing_event_exists(database: &D1Database, event: &BillingWebhookEvent) -> Result<bool> {
    Ok(database
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare("SELECT event_id FROM billing_events WHERE provider = ? AND event_id = ?")
        .bind(&[text(event.provider.as_str()), text(&event.event_id)])?
        .first::<BillingEventRow>(None)
        .await?
        .is_some())
}

fn billing_event_statement(
    database: &D1Database,
    event: &BillingWebhookEvent,
) -> Result<worker::D1PreparedStatement> {
    database
        .prepare(
            "INSERT INTO billing_events(provider, event_id, event_ts, processed_at) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(&[
            text(event.provider.as_str()),
            text(&event.event_id),
            integer(event.event_ts)?,
            integer(now_seconds())?,
        ])
}

fn subscription_terms(
    validity_json: &str,
) -> Result<(
    i64,
    Option<copylocker_server_core::policy::PerpetualFallback>,
)> {
    match serde_json::from_str::<Validity>(validity_json) {
        Ok(Validity::Subscription {
            dunning_grace_secs,
            fallback,
            ..
        }) => Ok((dunning_grace_secs, fallback)),
        _ => Err(worker::Error::RustError(
            "billing license policy is not a valid subscription".into(),
        )),
    }
}

fn normalize(
    provider: BillingProvider,
    value: &Value,
) -> std::result::Result<Option<BillingWebhookEvent>, ()> {
    match provider {
        BillingProvider::Stripe => normalize_stripe(value),
        BillingProvider::Paddle => normalize_paddle(value),
        BillingProvider::LemonSqueezy => normalize_lemonsqueezy(value),
    }
}

fn normalize_stripe(value: &Value) -> std::result::Result<Option<BillingWebhookEvent>, ()> {
    let event_id = string_at(value, &["id"]).ok_or(())?;
    let event_ts = timestamp_at(value, &["created"]).ok_or(())?;
    let event_type = string_at(value, &["type"]).ok_or(())?;
    let object = value_at(value, &["data", "object"]).ok_or(())?;
    let metadata = value_at(object, &["metadata"]);
    let external_id = string_at(object, &["subscription"])
        .or_else(|| string_at(object, &["subscription_id"]))
        .or_else(|| metadata.and_then(|meta| string_at(meta, &["subscription_id"])))
        .or_else(|| {
            event_type
                .starts_with("customer.subscription.")
                .then(|| string_at(object, &["id"]))
                .flatten()
        });
    let event_kind = match event_type {
        "checkout.session.completed" | "customer.subscription.created" => {
            let license_id = metadata
                .and_then(|meta| string_at(meta, &["copylocker_license_id"]))
                .and_then(|id| decode_hex_exact(id, 16))
                .ok_or(())?;
            let (period_start, period_end) = period_fields(object, metadata).ok_or(())?;
            BillingEventKind::Started {
                license_id,
                period_start,
                period_end,
                billing_period: billing_period(metadata, period_start, period_end),
            }
        }
        "invoice.paid" | "invoice.payment_succeeded" => {
            let (period_start, period_end) = period_fields(object, metadata).ok_or(())?;
            BillingEventKind::Renewed {
                period_start,
                period_end,
            }
        }
        "invoice.payment_failed" => BillingEventKind::PaymentFailed,
        "invoice.payment_action_required" => BillingEventKind::PaymentFailed,
        "customer.subscription.resumed" => BillingEventKind::PaymentRecovered,
        "customer.subscription.updated"
            if bool_at(object, &["cancel_at_period_end"]) == Some(true) =>
        {
            BillingEventKind::CancelAtPeriodEnd
        }
        "customer.subscription.updated" => BillingEventKind::PaymentRecovered,
        "customer.subscription.deleted" => BillingEventKind::PeriodEnded,
        "charge.refunded" => BillingEventKind::RefundReported,
        _ => return Ok(None),
    };
    Ok(Some(new_event(
        BillingProvider::Stripe,
        event_id,
        event_ts,
        external_id.ok_or(())?,
        event_kind,
    )))
}

fn normalize_paddle(value: &Value) -> std::result::Result<Option<BillingWebhookEvent>, ()> {
    let event_id = string_at(value, &["event_id"]).ok_or(())?;
    let event_ts = timestamp_at(value, &["occurred_at"]).ok_or(())?;
    let event_type = string_at(value, &["event_type"]).ok_or(())?;
    let data = value_at(value, &["data"]).ok_or(())?;
    let custom = value_at(data, &["custom_data"]);
    let external_id = string_at(data, &["subscription_id"]).or_else(|| {
        event_type
            .starts_with("subscription.")
            .then(|| string_at(data, &["id"]))
            .flatten()
    });
    let event_kind = match event_type {
        "subscription.created" => {
            let license_id = custom
                .and_then(|value| string_at(value, &["copylocker_license_id"]))
                .and_then(|id| decode_hex_exact(id, 16))
                .ok_or(())?;
            let (period_start, period_end) = paddle_period(data).ok_or(())?;
            BillingEventKind::Started {
                license_id,
                period_start,
                period_end,
                billing_period: billing_period(custom, period_start, period_end),
            }
        }
        "transaction.completed" => {
            let (period_start, period_end) = paddle_period(data).ok_or(())?;
            BillingEventKind::Renewed {
                period_start,
                period_end,
            }
        }
        "subscription.past_due" => BillingEventKind::PaymentFailed,
        "subscription.activated" | "subscription.resumed" => BillingEventKind::PaymentRecovered,
        "subscription.canceled" => BillingEventKind::PeriodEnded,
        "transaction.refunded" => BillingEventKind::RefundReported,
        _ => return Ok(None),
    };
    Ok(Some(new_event(
        BillingProvider::Paddle,
        event_id,
        event_ts,
        external_id.ok_or(())?,
        event_kind,
    )))
}

fn normalize_lemonsqueezy(value: &Value) -> std::result::Result<Option<BillingWebhookEvent>, ()> {
    let meta = value_at(value, &["meta"]).ok_or(())?;
    let data = value_at(value, &["data"]).ok_or(())?;
    let attrs = value_at(data, &["attributes"]).ok_or(())?;
    let custom = value_at(meta, &["custom_data"]);
    let event_id = string_at(meta, &["webhook_id"]).ok_or(())?;
    let event_ts = timestamp_at(meta, &["event_created_at"]).ok_or(())?;
    let event_type = string_at(meta, &["event_name"]).ok_or(())?;
    let external_id = string_at(attrs, &["subscription_id"])
        .or_else(|| string_at(data, &["id"]))
        .ok_or(())?;
    let event_kind = match event_type {
        "subscription_created" => {
            let license_id = custom
                .and_then(|value| string_at(value, &["copylocker_license_id"]))
                .and_then(|id| decode_hex_exact(id, 16))
                .ok_or(())?;
            let (period_start, period_end) = lemon_period(attrs).ok_or(())?;
            BillingEventKind::Started {
                license_id,
                period_start,
                period_end,
                billing_period: billing_period(custom, period_start, period_end),
            }
        }
        "subscription_payment_success" => {
            let (period_start, period_end) = lemon_period(attrs).ok_or(())?;
            BillingEventKind::Renewed {
                period_start,
                period_end,
            }
        }
        "subscription_payment_failed" => BillingEventKind::PaymentFailed,
        "subscription_resumed" => BillingEventKind::PaymentRecovered,
        "subscription_cancelled" => BillingEventKind::CancelAtPeriodEnd,
        "subscription_expired" => BillingEventKind::PeriodEnded,
        "subscription_payment_refunded" => BillingEventKind::RefundReported,
        _ => return Ok(None),
    };
    Ok(Some(new_event(
        BillingProvider::LemonSqueezy,
        event_id,
        event_ts,
        external_id,
        event_kind,
    )))
}

fn new_event(
    provider: BillingProvider,
    event_id: &str,
    event_ts: i64,
    external_id: &str,
    event_kind: BillingEventKind,
) -> BillingWebhookEvent {
    BillingWebhookEvent {
        event: BILLING_WEBHOOK_EVENT.to_owned(),
        schema_version: 1,
        provider,
        event_id: event_id.to_owned(),
        event_ts,
        external_id: external_id.to_owned(),
        event_kind,
    }
}

fn period_fields(object: &Value, metadata: Option<&Value>) -> Option<(i64, i64)> {
    let start = timestamp_at(object, &["current_period_start"])
        .or_else(|| timestamp_at(object, &["period_start"]))
        .or_else(|| metadata.and_then(|value| timestamp_at(value, &["current_period_start"])))?;
    let end = timestamp_at(object, &["current_period_end"])
        .or_else(|| timestamp_at(object, &["period_end"]))
        .or_else(|| metadata.and_then(|value| timestamp_at(value, &["current_period_end"])))?;
    valid_period(start, end).then_some((start, end))
}

fn paddle_period(data: &Value) -> Option<(i64, i64)> {
    let period = value_at(data, &["current_billing_period"])?;
    let start = timestamp_at(period, &["starts_at"])?;
    let end = timestamp_at(period, &["ends_at"])?;
    valid_period(start, end).then_some((start, end))
}

fn lemon_period(attrs: &Value) -> Option<(i64, i64)> {
    let start = timestamp_at(attrs, &["current_period_start"])?;
    let end = timestamp_at(attrs, &["current_period_end"])?;
    valid_period(start, end).then_some((start, end))
}

fn billing_period(metadata: Option<&Value>, start: i64, end: i64) -> String {
    metadata
        .and_then(|value| string_at(value, &["billing_period"]))
        .map(str::to_owned)
        .unwrap_or_else(|| {
            if end.saturating_sub(start) >= 300 * 86_400 {
                "annual".to_owned()
            } else {
                "monthly".to_owned()
            }
        })
}

fn verify_request_signature(
    request: &Request,
    provider: BillingProvider,
    secret: &[u8],
    body: &[u8],
) -> Result<bool> {
    let header_name = match provider {
        BillingProvider::Stripe => "Stripe-Signature",
        BillingProvider::Paddle => "Paddle-Signature",
        BillingProvider::LemonSqueezy => "X-Signature",
    };
    let Some(header) = request.headers().get(header_name)? else {
        return Ok(false);
    };
    Ok(match provider {
        BillingProvider::Stripe => verify_timestamped_signature(&header, ',', '.', secret, body),
        BillingProvider::Paddle => verify_timestamped_signature(&header, ';', ':', secret, body),
        BillingProvider::LemonSqueezy => verify_hmac(secret, body, header.trim()),
    })
}

fn verify_timestamped_signature(
    header: &str,
    separator: char,
    payload_separator: char,
    secret: &[u8],
    body: &[u8],
) -> bool {
    let mut timestamp = None;
    let mut signatures = Vec::new();
    for part in header.split(separator) {
        let Some((name, value)) = part.trim().split_once('=') else {
            continue;
        };
        match name {
            "t" | "ts" => timestamp = value.parse::<i64>().ok(),
            "v1" | "h1" => signatures.push(value),
            _ => {}
        }
    }
    let Some(timestamp) = timestamp else {
        return false;
    };
    if now_seconds().abs_diff(timestamp) > SIGNATURE_TOLERANCE_SECS as u64 {
        return false;
    }
    let mut payload = timestamp.to_string().into_bytes();
    payload.push(payload_separator as u8);
    payload.extend_from_slice(body);
    signatures
        .into_iter()
        .any(|signature| verify_hmac(secret, &payload, signature))
}

fn verify_hmac(secret: &[u8], payload: &[u8], signature_hex: &str) -> bool {
    let Some(signature) = decode_hex_exact(signature_hex, 32) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret) else {
        return false;
    };
    mac.update(payload);
    mac.verify_slice(&signature).is_ok()
}

async fn load_secret(env: &Env, provider: BillingProvider) -> Result<Secret<String>> {
    let mut value = if is_test_environment(env) {
        env.var(provider.test_secret_binding())?.to_string()
    } else {
        env.secret_store(provider.production_secret_binding())?
            .get()
            .await?
            .ok_or_else(|| worker::Error::RustError("webhook secret is missing".into()))?
    };
    if value.is_empty() || value.len() > 1024 {
        value.zeroize();
        return Err(worker::Error::RustError(
            "webhook secret has an invalid length".into(),
        ));
    }
    Ok(Secret::new(value))
}

fn is_json_request(request: &Request) -> Result<bool> {
    let content_type = request.headers().get("Content-Type")?;
    let encoding = request.headers().get("Content-Encoding")?;
    let valid_type = content_type.is_some_and(|value| {
        value
            .split_once(';')
            .map_or(value.as_str(), |(media_type, _)| media_type)
            .trim()
            .eq_ignore_ascii_case("application/json")
    });
    let valid_encoding = encoding
        .as_deref()
        .is_none_or(|value| value.is_empty() || value.eq_ignore_ascii_case("identity"));
    Ok(valid_type && valid_encoding)
}

fn is_test_environment(env: &Env) -> bool {
    env.var("ENVIRONMENT")
        .map(|value| value.to_string() == "test")
        .unwrap_or(false)
}

fn value_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(value, |current, key| current.get(key))
}

fn string_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    value_at(value, path)?.as_str()
}

fn bool_at(value: &Value, path: &[&str]) -> Option<bool> {
    value_at(value, path)?.as_bool()
}

fn timestamp_at(value: &Value, path: &[&str]) -> Option<i64> {
    let value = value_at(value, path)?;
    value
        .as_i64()
        .or_else(|| value.as_str()?.parse::<i64>().ok())
        .or_else(|| value.as_str().and_then(parse_rfc3339))
}

fn parse_rfc3339(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
        || !value.ends_with('Z')
    {
        return None;
    }
    let year = parse_decimal(bytes.get(0..4)?)?;
    let month = parse_decimal(bytes.get(5..7)?)?;
    let day = parse_decimal(bytes.get(8..10)?)?;
    let hour = parse_decimal(bytes.get(11..13)?)?;
    let minute = parse_decimal(bytes.get(14..16)?)?;
    let second = parse_decimal(bytes.get(17..19)?)?;
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    days.checked_mul(86_400)?
        .checked_add(hour.checked_mul(3_600)?)?
        .checked_add(minute.checked_mul(60)?)?
        .checked_add(second)
}

fn parse_decimal(bytes: &[u8]) -> Option<i64> {
    bytes.iter().try_fold(0i64, |value, byte| {
        byte.is_ascii_digit()
            .then(|| value.saturating_mul(10) + i64::from(byte - b'0'))
    })
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if is_leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn is_leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    let adjusted_year = year.checked_sub(i64::from(month <= 2))?;
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year.checked_sub(399)?
    } / 400;
    let year_of_era = adjusted_year.checked_sub(era.checked_mul(400)?)?;
    let shifted_month = month.checked_add(if month > 2 { -3 } else { 9 })?;
    let day_of_year = 153i64
        .checked_mul(shifted_month)?
        .checked_add(2)?
        .checked_div(5)?
        .checked_add(day.checked_sub(1)?)?;
    let day_of_era = year_of_era
        .checked_mul(365)?
        .checked_add(year_of_era / 4)?
        .checked_sub(year_of_era / 100)?
        .checked_add(day_of_year)?;
    era.checked_mul(146_097)?
        .checked_add(day_of_era)?
        .checked_sub(719_468)
}

fn valid_identifier(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-.:/".contains(&byte))
}

fn valid_period(start: i64, end: i64) -> bool {
    (0..=MAX_SAFE_INTEGER).contains(&start) && (0..=MAX_SAFE_INTEGER).contains(&end) && start < end
}

fn decode_hex_exact(value: &str, expected_len: usize) -> Option<Vec<u8>> {
    if value.len() != expected_len.checked_mul(2)? {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(*pair.first()?)?;
            let low = hex_nibble(*pair.get(1)?)?;
            Some((high << 4) | low)
        })
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let high = HEX.get(usize::from(byte >> 4)).copied().unwrap_or(b'0');
        let low = HEX.get(usize::from(byte & 0x0f)).copied().unwrap_or(b'0');
        encoded.push(char::from(high));
        encoded.push(char::from(low));
    }
    encoded
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn state_name(state: SubscriptionState) -> &'static str {
    match state {
        SubscriptionState::Active => "active",
        SubscriptionState::PastDue => "past_due",
        SubscriptionState::Canceling => "canceling",
        SubscriptionState::Suspended => "suspended",
        SubscriptionState::Ended => "ended",
        SubscriptionState::Expired => "expired",
        SubscriptionState::PerpetualFallback => "perpetual_fallback",
    }
}

fn parse_state(value: &str) -> Result<SubscriptionState> {
    match value {
        "active" => Ok(SubscriptionState::Active),
        "past_due" => Ok(SubscriptionState::PastDue),
        "canceling" => Ok(SubscriptionState::Canceling),
        "suspended" => Ok(SubscriptionState::Suspended),
        "ended" => Ok(SubscriptionState::Ended),
        "expired" => Ok(SubscriptionState::Expired),
        "perpetual_fallback" => Ok(SubscriptionState::PerpetualFallback),
        _ => Err(worker::Error::RustError(
            "subscription row has an invalid state".into(),
        )),
    }
}

fn now_seconds() -> i64 {
    i64::try_from(Date::now().as_millis() / 1000).unwrap_or(i64::MAX)
}

fn blob(value: &[u8]) -> JsValue {
    JsValue::from(&D1Type::Blob(value))
}

fn text(value: &str) -> JsValue {
    JsValue::from_str(value)
}

fn optional_text(value: Option<&str>) -> JsValue {
    value.map_or(JsValue::NULL, JsValue::from_str)
}

fn integer(value: i64) -> Result<JsValue> {
    if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&value) {
        return Err(worker::Error::RustError(
            "billing integer exceeds JavaScript safe range".into(),
        ));
    }
    Ok(JsValue::from_f64(value as f64))
}

fn optional_integer(value: Option<i64>) -> Result<JsValue> {
    value.map_or(Ok(JsValue::NULL), integer)
}

#[derive(Debug, Deserialize)]
struct LicensePolicyRow {
    validity_json: String,
}

#[derive(Debug, Deserialize)]
struct BillingEventRow {
    #[allow(dead_code)]
    event_id: String,
}

#[derive(Debug, Deserialize)]
struct DueSubscriptionRow {
    license_id: Vec<u8>,
    provider: String,
    external_id: String,
    state: String,
    current_period_end: i64,
    dunning_until: Option<i64>,
    refund_observe_until: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct SubscriptionRow {
    license_id: Vec<u8>,
    provider: String,
    external_id: String,
    state: String,
    current_period_start: i64,
    current_period_end: i64,
    dunning_until: Option<i64>,
    continuous_paid_months: u32,
    fallback_earned_at: Option<i64>,
    canceled_at: Option<i64>,
    updated_at: i64,
    refund_observe_until: Option<i64>,
    validity_json: String,
}

impl SubscriptionRow {
    fn to_subscription(&self) -> Result<Subscription> {
        Ok(Subscription {
            provider: self.provider.clone(),
            external_id: self.external_id.clone(),
            state: parse_state(&self.state)?,
            current_period_start: self.current_period_start,
            current_period_end: self.current_period_end,
            dunning_until: self.dunning_until,
            continuous_paid_months: self.continuous_paid_months,
            fallback_earned_at: self.fallback_earned_at,
            canceled_at: self.canceled_at,
            updated_at: self.updated_at,
            processed_events: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_parser_handles_fractional_seconds_and_leap_days() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339("2024-02-29T12:34:56.123Z"),
            Some(1_709_210_096)
        );
        assert_eq!(parse_rfc3339("2023-02-29T00:00:00Z"), None);
    }

    #[test]
    fn all_three_providers_normalize_subscription_events() -> Result<(), Box<dyn std::error::Error>>
    {
        let license = "01010101010101010101010101010101";
        let stripe = serde_json::json!({
            "id": "evt_stripe",
            "type": "customer.subscription.created",
            "created": 1_700_000_000,
            "data": { "object": {
                "id": "sub_stripe",
                "current_period_start": 1_700_000_000,
                "current_period_end": 1_702_592_000,
                "metadata": { "copylocker_license_id": license }
            }}
        });
        let paddle = serde_json::json!({
            "event_id": "evt_paddle",
            "event_type": "subscription.created",
            "occurred_at": "2023-11-14T22:13:20Z",
            "data": {
                "id": "sub_paddle",
                "current_billing_period": {
                    "starts_at": "2023-11-14T22:13:20Z",
                    "ends_at": "2023-12-14T22:13:20Z"
                },
                "custom_data": { "copylocker_license_id": license }
            }
        });
        let lemon = serde_json::json!({
            "meta": {
                "webhook_id": "evt_lemon",
                "event_name": "subscription_created",
                "event_created_at": "2023-11-14T22:13:20Z",
                "custom_data": { "copylocker_license_id": license }
            },
            "data": {
                "id": "sub_lemon",
                "attributes": {
                    "current_period_start": "2023-11-14T22:13:20Z",
                    "current_period_end": "2023-12-14T22:13:20Z"
                }
            }
        });

        for (provider, payload) in [
            (BillingProvider::Stripe, stripe),
            (BillingProvider::Paddle, paddle),
            (BillingProvider::LemonSqueezy, lemon),
        ] {
            let event = normalize(provider, &payload)
                .map_err(|()| std::io::Error::other("provider fixture did not parse"))?
                .ok_or_else(|| std::io::Error::other("provider fixture was not supported"))?;
            assert!(event.is_valid(), "{provider:?} normalized invalid data");
            assert!(matches!(event.event_kind, BillingEventKind::Started { .. }));
        }
        Ok(())
    }

    #[test]
    fn hmac_verification_rejects_modified_payloads() -> Result<(), Box<dyn std::error::Error>> {
        let secret = b"secret";
        let body = b"payload";
        let mut mac = Hmac::<Sha256>::new_from_slice(secret)
            .map_err(|_| std::io::Error::other("HMAC rejected the fixture key"))?;
        mac.update(body);
        let signature = mac.finalize().into_bytes();
        let signature_hex: String = signature.iter().map(|byte| format!("{byte:02x}")).collect();

        assert!(verify_hmac(secret, body, &signature_hex));
        assert!(!verify_hmac(secret, b"modified", &signature_hex));
        Ok(())
    }
}
