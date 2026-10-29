-- Keep user selections separate from the latest automatic identification.
ALTER TABLE devices ADD COLUMN device_type_override TEXT;
