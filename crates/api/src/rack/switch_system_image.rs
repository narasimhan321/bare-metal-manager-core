/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::collections::HashMap;
use std::path::PathBuf;

use db::db_read::DbReader;
use db::rack_firmware as db_rack_firmware;
use model::rack::Rack;
use serde::Deserialize;

const SWITCH_DEVICE_TYPE: &str = "Switch Tray";
const DEFAULT_FIRMWARE_TYPE: &str = "prod";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSwitchSystemImage {
    pub image_filename: String,
    pub local_file_path: String,
    pub version: String,
}

#[derive(Debug, Deserialize)]
struct SwitchSystemImageLookupTable {
    #[serde(default)]
    switch_system_images: HashMap<String, HashMap<String, SwitchSystemImageLookupEntry>>,
}

#[derive(Debug, Deserialize)]
struct SwitchSystemImageLookupEntry {
    image_filename: String,
    version: String,
}

pub fn resolve_switch_system_image_from_lookup(
    firmware_id: &str,
    parsed_components: &serde_json::Value,
    firmware_type: &str,
) -> Result<ResolvedSwitchSystemImage, String> {
    let lookup: SwitchSystemImageLookupTable =
        serde_json::from_value(parsed_components.clone()).map_err(|e| {
            format!("failed to parse switch system image lookup table: {e}")
        })?;

    let key = format!("NVOS_{}", firmware_type.to_lowercase());
    let entry = lookup
        .switch_system_images
        .get(SWITCH_DEVICE_TYPE)
        .ok_or_else(|| format!("missing switch system images for {SWITCH_DEVICE_TYPE}"))?
        .get(&key)
        .ok_or_else(|| format!("missing switch system image lookup entry: {key}"))?;

    let local_file_path = PathBuf::from("/forge-boot-artifacts/blobs/internal/fw")
        .join("rack_firmware")
        .join(firmware_id)
        .join(&entry.image_filename)
        .display()
        .to_string();

    Ok(ResolvedSwitchSystemImage {
        image_filename: entry.image_filename.clone(),
        local_file_path,
        version: entry.version.clone(),
    })
}

pub async fn resolve_desired_switch_system_image(
    txn: impl DbReader<'_>,
    rack: &Rack,
    firmware_type: Option<&str>,
) -> Result<ResolvedSwitchSystemImage, String> {
    let firmware_id = rack
        .desired_switch_nvos_firmware_id
        .as_deref()
        .ok_or_else(|| "rack has no desired_switch_nvos_firmware_id".to_string())?;

    let rack_firmware = db_rack_firmware::find_by_id(txn, firmware_id)
        .await
        .map_err(|e| format!("failed to load rack firmware {firmware_id}: {e}"))?;

    if !rack_firmware.available {
        return Err(format!("rack firmware {firmware_id} is not available"));
    }

    let parsed_components = rack_firmware
        .parsed_components
        .as_ref()
        .map(|j| &j.0)
        .ok_or_else(|| format!("rack firmware {firmware_id} has no parsed_components"))?;

    resolve_switch_system_image_from_lookup(
        firmware_id,
        parsed_components,
        firmware_type.unwrap_or(DEFAULT_FIRMWARE_TYPE),
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn resolve_switch_system_image_from_lookup_success() {
        let parsed_components = json!({
            "devices": {},
            "switch_system_images": {
                "Switch Tray": {
                    "NVOS_prod": {
                        "component": "NVOS",
                        "package_name": "GB200NVL72_NVOS",
                        "version": "25.02.2553",
                        "image_filename": "nvos-amd64-25.02.2553.bin",
                        "location_type": "HTTPS",
                        "firmware_type": "prod"
                    }
                }
            }
        });

        let resolved =
            resolve_switch_system_image_from_lookup("fw-001", &parsed_components, "prod").unwrap();

        assert_eq!(resolved.image_filename, "nvos-amd64-25.02.2553.bin");
        assert_eq!(resolved.version, "25.02.2553");
        assert_eq!(
            resolved.local_file_path,
            "/forge-boot-artifacts/blobs/internal/fw/rack_firmware/fw-001/nvos-amd64-25.02.2553.bin"
        );
    }

    #[test]
    fn resolve_switch_system_image_from_lookup_missing_entry() {
        let parsed_components = json!({
            "devices": {},
            "switch_system_images": {
                "Switch Tray": {}
            }
        });

        let err =
            resolve_switch_system_image_from_lookup("fw-001", &parsed_components, "prod")
                .unwrap_err();

        assert!(err.contains("missing switch system image lookup entry"));
    }
}
