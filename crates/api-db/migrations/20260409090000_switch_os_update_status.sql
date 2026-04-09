-- Add per-switch OS update tracking for switch reprovisioning.
ALTER TABLE
    switches
ADD
    COLUMN os_update_status JSONB;
