CREATE TABLE notification_card_receipts (
    event_id uuid PRIMARY KEY,
    worker_url text NOT NULL,
    message_id text UNIQUE,
    appeal_id uuid NOT NULL REFERENCES appeals(id) ON DELETE CASCADE,
    appeal_revision bigint NOT NULL,
    recipient text NOT NULL,
    approval_ids jsonb NOT NULL,
    last_state_hash text NOT NULL,
    delivery_deadline timestamptz NOT NULL DEFAULT (NOW() + interval '55 minutes'),
    next_check_at timestamptz NOT NULL DEFAULT NOW(),
    lease_owner uuid,
    lease_until timestamptz,
    closed boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW()
);

CREATE INDEX notification_cards_due ON notification_card_receipts(worker_url, next_check_at) WHERE NOT closed;
CREATE INDEX notification_cards_appeal ON notification_card_receipts(appeal_id, appeal_revision);
