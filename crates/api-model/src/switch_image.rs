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

use chrono::{DateTime, Utc};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchImage {
    pub id: String,
    pub version: String,
    pub image_filename: String,
    pub local_file_path: String,
    pub available: bool,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
}

impl<'r> FromRow<'r, PgRow> for SwitchImage {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(SwitchImage {
            id: row.try_get("id")?,
            version: row.try_get("version")?,
            image_filename: row.try_get("image_filename")?,
            local_file_path: row.try_get("local_file_path")?,
            available: row.try_get("available")?,
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
        })
    }
}
