/**
 * Drift check between the ts-rs-generated bindings (`bindings/`, regenerated
 * from the Rust wire types by `scripts/check-admin-sdk-bindings.sh`) and the
 * hand-written Admin API wire types (`src/types.ts`).
 *
 * Two assertions per mapped pair:
 *
 * 1. `AssertWireAssignable<Gen, Hand>` — every response the Rust type can
 *    serialize is accepted by the hand-written type. This catches renames,
 *    retyped fields, and narrowed unions that would break response parsing.
 * 2. `AssertRequiredSubset<Hand, Gen>` — the hand-written type never
 *    *requires* a field the Rust serialization may omit (hand-written types
 *    mark `#[serde(default)]` fields optional for request ergonomics).
 *
 * Union types only get assertion 1 (`keyof` does not distribute over unions
 * in a useful way). A type error here means the hand-written types drifted
 * from the Rust source of truth: update `src/types.ts`, never this file's
 * assertions, unless the Rust wire type itself changed (in which case
 * regenerate the bindings and update both).
 */

import type { Entitlements as GenEntitlements } from './bindings/Entitlements'
import type { EntitlementSpec as GenEntitlementSpec } from './bindings/EntitlementSpec'
import type { FallbackScopeAt as GenFallbackScopeAt } from './bindings/FallbackScopeAt'
import type { Feature as GenFeature } from './bindings/Feature'
import type { FeatureGroup as GenFeatureGroup } from './bindings/FeatureGroup'
import type { Grant as GenGrant } from './bindings/Grant'
import type { GrantTarget as GenGrantTarget } from './bindings/GrantTarget'
import type { GroupMembers as GenGroupMembers } from './bindings/GroupMembers'
import type { LimitMergePolicy as GenLimitMergePolicy } from './bindings/LimitMergePolicy'
import type { MetricDefinition as GenMetricDefinition } from './bindings/MetricDefinition'
import type { MetricTier as GenMetricTier } from './bindings/MetricTier'
import type { Mode as GenMode } from './bindings/Mode'
import type { OfflineUpgradePolicy as GenOfflineUpgradePolicy } from './bindings/OfflineUpgradePolicy'
import type { PerpetualFallback as GenPerpetualFallback } from './bindings/PerpetualFallback'
import type { Policy as GenPolicy } from './bindings/Policy'
import type { QueryMeta as GenQueryMeta } from './bindings/QueryMeta'
import type { RuntimeSpec as GenRuntimeSpec } from './bindings/RuntimeSpec'
import type { SeatSpec as GenSeatSpec } from './bindings/SeatSpec'
import type { Source as GenSource } from './bindings/Source'
import type { SubscriptionHint as GenSubscriptionHint } from './bindings/SubscriptionHint'
import type { SubscriptionState as GenSubscriptionState } from './bindings/SubscriptionState'
import type { Tier as GenTier } from './bindings/Tier'
import type { TrialScope as GenTrialScope } from './bindings/TrialScope'
import type { Validity as GenValidity } from './bindings/Validity'
import type { VersionScope as GenVersionScope } from './bindings/VersionScope'
import type { VtSignature as GenVtSignature } from './bindings/VtSignature'
import type {
  AnalyticsSource,
  Entitlements,
  EntitlementSpec,
  FallbackScopeAt,
  Feature,
  FeatureGroup,
  Grant,
  GrantTarget,
  GroupMembers,
  LimitMergePolicy,
  MetricDefinition,
  MetricTier,
  Mode,
  OfflineUpgradePolicy,
  PerpetualFallback,
  Policy,
  QueryMeta,
  RuntimeSpec,
  SeatSpec,
  SubscriptionHint,
  SubscriptionState,
  Tier,
  TrialScope,
  Validity,
  VersionScope,
  VtSignature,
} from './src/types.js'

type AssertWireAssignable<Gen, Hand> = Gen extends Hand ? true : false

type RequiredKeys<T> = {
  [K in keyof T]-?: Record<string, never> extends Pick<T, K> ? never : K
}[keyof T]

type AssertRequiredSubset<Hand, Gen> = RequiredKeys<Hand> extends RequiredKeys<Gen>
  ? true
  : false

type IsTrue<T extends true> = T

// copylocker-types `entitlements.rs` / `state.rs`
type _VersionScope = IsTrue<AssertWireAssignable<GenVersionScope, VersionScope>>
type _SubscriptionState = IsTrue<AssertWireAssignable<GenSubscriptionState, SubscriptionState>>
type _SubscriptionHintWire = IsTrue<AssertWireAssignable<GenSubscriptionHint, SubscriptionHint>>
type _SubscriptionHintRequired = IsTrue<AssertRequiredSubset<SubscriptionHint, GenSubscriptionHint>>
type _EntitlementsWire = IsTrue<AssertWireAssignable<GenEntitlements, Entitlements>>
type _EntitlementsRequired = IsTrue<AssertRequiredSubset<Entitlements, GenEntitlements>>
type _Mode = IsTrue<AssertWireAssignable<GenMode, Mode>>

// copylocker-server-core `entitlement.rs`
type _GrantTarget = IsTrue<AssertWireAssignable<GenGrantTarget, GrantTarget>>
type _GrantWire = IsTrue<AssertWireAssignable<GenGrant, Grant>>
type _GrantRequired = IsTrue<AssertRequiredSubset<Grant, GenGrant>>
type _LimitMergePolicy = IsTrue<AssertWireAssignable<GenLimitMergePolicy, LimitMergePolicy>>
type _EntitlementSpecWire = IsTrue<AssertWireAssignable<GenEntitlementSpec, EntitlementSpec>>
type _EntitlementSpecRequired = IsTrue<AssertRequiredSubset<EntitlementSpec, GenEntitlementSpec>>

// copylocker-server-core `policy.rs`
type _Validity = IsTrue<AssertWireAssignable<GenValidity, Validity>>
type _TrialScope = IsTrue<AssertWireAssignable<GenTrialScope, TrialScope>>
type _PerpetualFallbackWire = IsTrue<AssertWireAssignable<GenPerpetualFallback, PerpetualFallback>>
type _PerpetualFallbackRequired = IsTrue<
  AssertRequiredSubset<PerpetualFallback, GenPerpetualFallback>
>
type _FallbackScopeAt = IsTrue<AssertWireAssignable<GenFallbackScopeAt, FallbackScopeAt>>
type _SeatSpecWire = IsTrue<AssertWireAssignable<GenSeatSpec, SeatSpec>>
type _SeatSpecRequired = IsTrue<AssertRequiredSubset<SeatSpec, GenSeatSpec>>
type _RuntimeSpecWire = IsTrue<AssertWireAssignable<GenRuntimeSpec, RuntimeSpec>>
type _RuntimeSpecRequired = IsTrue<AssertRequiredSubset<RuntimeSpec, GenRuntimeSpec>>
type _VtSignature = IsTrue<AssertWireAssignable<GenVtSignature, VtSignature>>
type _OfflineUpgradePolicy = IsTrue<AssertWireAssignable<GenOfflineUpgradePolicy, OfflineUpgradePolicy>>
type _PolicyWire = IsTrue<AssertWireAssignable<GenPolicy, Policy>>
type _PolicyRequired = IsTrue<AssertRequiredSubset<Policy, GenPolicy>>

// copylocker-server-core `catalog.rs`
type _FeatureWire = IsTrue<AssertWireAssignable<GenFeature, Feature>>
type _FeatureRequired = IsTrue<AssertRequiredSubset<Feature, GenFeature>>
type _GroupMembersWire = IsTrue<AssertWireAssignable<GenGroupMembers, GroupMembers>>
type _GroupMembersRequired = IsTrue<AssertRequiredSubset<GroupMembers, GenGroupMembers>>
type _FeatureGroupWire = IsTrue<AssertWireAssignable<GenFeatureGroup, FeatureGroup>>
type _FeatureGroupRequired = IsTrue<AssertRequiredSubset<FeatureGroup, GenFeatureGroup>>
type _TierWire = IsTrue<AssertWireAssignable<GenTier, Tier>>
type _TierRequired = IsTrue<AssertRequiredSubset<Tier, GenTier>>

// copylocker-server-core `analytics/`
type _Source = IsTrue<AssertWireAssignable<GenSource, AnalyticsSource>>
type _QueryMetaWire = IsTrue<AssertWireAssignable<GenQueryMeta, QueryMeta>>
type _QueryMetaRequired = IsTrue<AssertRequiredSubset<QueryMeta, GenQueryMeta>>
type _MetricTier = IsTrue<AssertWireAssignable<GenMetricTier, MetricTier>>
type _MetricDefinitionWire = IsTrue<AssertWireAssignable<GenMetricDefinition, MetricDefinition>>
type _MetricDefinitionRequired = IsTrue<
  AssertRequiredSubset<MetricDefinition, GenMetricDefinition>
>
