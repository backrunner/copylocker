use serde::Deserialize;
use worker::{Env, MessageBatch, MessageExt, Result};

use crate::events::{
    AdminAuditEvent, AuditArchiveEvent, ProjectionEvent, ADMIN_AUDIT_ARCHIVE_EVENT,
    AUDIT_ARCHIVE_EVENT, LICENSE_PROJECTION_EVENT,
};
use crate::webhook::{BillingWebhookEvent, BILLING_WEBHOOK_EVENT};
use crate::{audit, projection, webhook};

pub(crate) async fn consume(batch: MessageBatch<serde_json::Value>, env: &Env) -> Result<()> {
    for message in batch.raw_iter() {
        let message_id = message.id();
        let header = match worker::serde_wasm_bindgen::from_value::<EventHeader>(message.body()) {
            Ok(header) => header,
            Err(error) => {
                log_invalid_event(&message_id, None, &error.to_string());
                message.ack();
                continue;
            }
        };

        let result = match header.event.as_str() {
            LICENSE_PROJECTION_EVENT => {
                let event =
                    worker::serde_wasm_bindgen::from_value::<ProjectionEvent>(message.body());
                match event {
                    Ok(event) if event.is_valid() => match env.d1("DB") {
                        Ok(database) => projection::apply(&database, &event).await,
                        Err(error) => Err(error),
                    },
                    Ok(_) => {
                        log_invalid_event(
                            &message_id,
                            Some(LICENSE_PROJECTION_EVENT),
                            "event validation failed",
                        );
                        message.ack();
                        continue;
                    }
                    Err(error) => {
                        log_invalid_event(
                            &message_id,
                            Some(LICENSE_PROJECTION_EVENT),
                            &error.to_string(),
                        );
                        message.ack();
                        continue;
                    }
                }
            }
            AUDIT_ARCHIVE_EVENT => {
                let event =
                    worker::serde_wasm_bindgen::from_value::<AuditArchiveEvent>(message.body());
                match event {
                    Ok(event) if event.is_valid() => audit::archive(env, &event).await,
                    Ok(_) => {
                        log_invalid_event(
                            &message_id,
                            Some(AUDIT_ARCHIVE_EVENT),
                            "event validation failed",
                        );
                        message.ack();
                        continue;
                    }
                    Err(error) => {
                        log_invalid_event(
                            &message_id,
                            Some(AUDIT_ARCHIVE_EVENT),
                            &error.to_string(),
                        );
                        message.ack();
                        continue;
                    }
                }
            }
            ADMIN_AUDIT_ARCHIVE_EVENT => {
                let event =
                    worker::serde_wasm_bindgen::from_value::<AdminAuditEvent>(message.body());
                match event {
                    Ok(event) if event.is_valid() => audit::archive_admin(env, &event).await,
                    Ok(_) => {
                        log_invalid_event(
                            &message_id,
                            Some(ADMIN_AUDIT_ARCHIVE_EVENT),
                            "event validation failed",
                        );
                        message.ack();
                        continue;
                    }
                    Err(error) => {
                        log_invalid_event(
                            &message_id,
                            Some(ADMIN_AUDIT_ARCHIVE_EVENT),
                            &error.to_string(),
                        );
                        message.ack();
                        continue;
                    }
                }
            }
            BILLING_WEBHOOK_EVENT => {
                let event =
                    worker::serde_wasm_bindgen::from_value::<BillingWebhookEvent>(message.body());
                match event {
                    Ok(event) if event.is_valid() => webhook::process(env, &event).await,
                    Ok(_) => {
                        log_invalid_event(
                            &message_id,
                            Some(BILLING_WEBHOOK_EVENT),
                            "event validation failed",
                        );
                        message.ack();
                        continue;
                    }
                    Err(error) => {
                        log_invalid_event(
                            &message_id,
                            Some(BILLING_WEBHOOK_EVENT),
                            &error.to_string(),
                        );
                        message.ack();
                        continue;
                    }
                }
            }
            event => {
                log_invalid_event(&message_id, Some(event), "unknown event type");
                message.ack();
                continue;
            }
        };

        match result {
            Ok(()) => message.ack(),
            Err(error) => {
                log_processing_error(&message_id, &header.event, &error);
                message.retry();
            }
        }
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
struct EventHeader {
    event: String,
}

fn log_invalid_event(message_id: &str, event: Option<&str>, reason: &str) {
    worker::console_error!(
        "{}",
        serde_json::json!({
            "level": "error",
            "message": "discarding invalid queue event",
            "queue_message_id": message_id,
            "event": event,
            "reason": reason
        })
    );
}

fn log_processing_error(message_id: &str, event: &str, error: &worker::Error) {
    worker::console_error!(
        "{}",
        serde_json::json!({
            "level": "error",
            "message": "queue event processing failed",
            "queue_message_id": message_id,
            "event": event,
            "error": error.to_string()
        })
    );
}
