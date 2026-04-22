-- Add an optimistic-locking version column to applications so concurrent
-- updates (e.g. simultaneous redirect_uris edits) can't silently
-- clobber each other. Existing rows start at 0; new writers bump it.
ALTER TABLE applications
    ADD COLUMN version INT NOT NULL DEFAULT 0;
