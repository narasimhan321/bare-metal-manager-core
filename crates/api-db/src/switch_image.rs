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

use model::switch_image::SwitchImage;
use sqlx::Error::RowNotFound;
use sqlx::PgConnection;

use crate::db_read::DbReader;
use crate::{DatabaseError, DatabaseResult};

pub async fn create(
    txn: &mut PgConnection,
    id: &str,
    version: &str,
    image_filename: &str,
    local_file_path: &str,
) -> DatabaseResult<SwitchImage> {
    let query = "INSERT INTO switch_image (id, version, image_filename, local_file_path) \
        VALUES ($1, $2, $3, $4) RETURNING *";

    sqlx::query_as(query)
        .bind(id)
        .bind(version)
        .bind(image_filename)
        .bind(local_file_path)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))
}

pub async fn find_by_id(txn: impl DbReader<'_>, id: &str) -> DatabaseResult<SwitchImage> {
    let query = "SELECT * FROM switch_image WHERE id = $1";
    let ret = sqlx::query_as(query).bind(id).fetch_one(txn).await;
    ret.map_err(|e| match e {
        RowNotFound => DatabaseError::NotFoundError {
            kind: "switch image",
            id: id.to_string(),
        },
        _ => DatabaseError::query(query, e),
    })
}

pub async fn find_by_version(
    txn: impl DbReader<'_>,
    version: &str,
) -> DatabaseResult<Vec<SwitchImage>> {
    let query = "SELECT * FROM switch_image WHERE version = $1 ORDER BY created DESC";
    sqlx::query_as(query)
        .bind(version)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn list_all(
    txn: impl DbReader<'_>,
    only_available: bool,
) -> DatabaseResult<Vec<SwitchImage>> {
    let query = if only_available {
        "SELECT * FROM switch_image WHERE available = true ORDER BY created DESC"
    } else {
        "SELECT * FROM switch_image ORDER BY created DESC"
    };

    sqlx::query_as(query)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn set_available(
    txn: &mut PgConnection,
    id: &str,
    available: bool,
) -> DatabaseResult<SwitchImage> {
    let query =
        "UPDATE switch_image SET available = $2, updated = NOW() WHERE id = $1 RETURNING *";

    sqlx::query_as(query)
        .bind(id)
        .bind(available)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))
}
