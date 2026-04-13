ALTER TABLE racks
ADD COLUMN desired_switch_nvos_firmware_id VARCHAR NULL
REFERENCES rack_firmware(id)
ON DELETE SET NULL;
