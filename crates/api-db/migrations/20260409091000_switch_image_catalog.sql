-- Create table to store switch OS image configurations.
CREATE TABLE switch_image(
    id VARCHAR(256) PRIMARY KEY,
    version VARCHAR NOT NULL,
    image_filename VARCHAR NOT NULL,
    local_file_path VARCHAR NOT NULL,
    available BOOLEAN NOT NULL DEFAULT false,
    created TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_switch_image_available ON switch_image(available);
CREATE INDEX idx_switch_image_created ON switch_image(created);
CREATE INDEX idx_switch_image_version ON switch_image(version);

-- Store the desired switch image selection at rack scope.
ALTER TABLE
    racks
ADD
    COLUMN desired_switch_image_id VARCHAR(256) REFERENCES switch_image(id);

CREATE INDEX idx_racks_desired_switch_image_id ON racks(desired_switch_image_id);
