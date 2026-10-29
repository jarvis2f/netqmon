-- Keep user selections separate from the latest automatic identification.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS device_type_override Nullable(String);
