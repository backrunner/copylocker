-- Refunds enter a review window before the licence is revoked. The subscription remains
-- suspended during this interval so an accidental provider refund cannot destroy access
-- permanently without an operator-visible delay.
ALTER TABLE subscriptions ADD COLUMN refund_observe_until INTEGER;

CREATE INDEX idx_subscriptions_refund_review
  ON subscriptions(refund_observe_until)
  WHERE refund_observe_until IS NOT NULL;
