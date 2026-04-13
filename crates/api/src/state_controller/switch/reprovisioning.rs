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

//! Handler for SwitchControllerState::ReProvisioning.

use carbide_uuid::switch::SwitchId;
use chrono::Utc;
use db::rack as db_rack;
use db::switch as db_switch;
use eyre::eyre;
use model::switch::{
    ReProvisioningState, Switch, SwitchControllerState, SwitchOsUpdateState,
    SwitchOsUpdateStatus,
};

use crate::rack::switch_system_image;
use crate::state_controller::state_handler::{
    StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};
use crate::state_controller::switch::context::SwitchStateHandlerContextObjects;

/// Handles the ReProvisioning state for a switch.
pub async fn handle_reprovisioning(
    switch_id: &SwitchId,
    state: &mut Switch,
    ctx: &mut StateHandlerContext<'_, SwitchStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<SwitchControllerState>, StateHandlerError> {
    let reprovisioning_state = match &state.controller_state.value {
        SwitchControllerState::ReProvisioning {
            reprovisioning_state,
        } => reprovisioning_state,
        _ => unreachable!("handle_reprovisioning called with non-ReProvisioning state"),
    };

    match reprovisioning_state {
        ReProvisioningState::WaitingForRackFirmwareUpgrade => {
            let mut txn = ctx.services.db_pool.begin().await?;
            db_switch::clear_switch_reprovisioning_requested(txn.as_mut(), *switch_id).await?;
            Ok(StateHandlerOutcome::transition(SwitchControllerState::Ready).with_txn(txn))
        }
        ReProvisioningState::OSUpdateStart => {
            let rack_id = state
                .rack_id
                .as_ref()
                .ok_or_else(|| StateHandlerError::MissingData {
                    object_id: switch_id.to_string(),
                    missing: "rack_id",
                })?;

            let mut txn = ctx.services.db_pool.begin().await?;
            let rack = db_rack::get(txn.as_mut(), rack_id).await?;
            let resolved = switch_system_image::resolve_desired_switch_system_image(
                txn.as_mut(),
                &rack,
                None,
            )
            .await
            .map_err(|e| {
                StateHandlerError::GenericError(eyre!(
                    "failed to resolve desired switch system image for rack {}: {}",
                    rack.id,
                    e
                ))
            })?;

            let rack_firmware_id = rack
                .desired_switch_nvos_firmware_id
                .clone()
                .ok_or_else(|| StateHandlerError::GenericError(eyre!(
                    "rack {} has no desired_switch_nvos_firmware_id",
                    rack.id
                )))?;

            let os_update_status = SwitchOsUpdateStatus {
                rack_firmware_id,
                image_version: resolved.version,
                image_filename: resolved.image_filename,
                local_file_path: resolved.local_file_path,
                job_id: None,
                status: SwitchOsUpdateState::Pending,
                status_message: Some(
                    "prepared switch OS update request from rack_firmware; RMS submission is pending"
                        .to_string(),
                ),
                started_at: Some(Utc::now()),
                ended_at: None,
                result_json: None,
            };

            db_switch::update_os_update_status(txn.as_mut(), *switch_id, Some(&os_update_status))
                .await?;

            Ok(StateHandlerOutcome::transition(
                SwitchControllerState::ReProvisioning {
                    reprovisioning_state: ReProvisioningState::OSUpdateWait,
                },
            )
            .with_txn(txn))
        }
        ReProvisioningState::OSUpdateWait => Ok(StateHandlerOutcome::wait(
            "switch OS update request is prepared; waiting for RMS submission/polling implementation"
                .into(),
        )),
    }
}
