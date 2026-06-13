// Copyright 2025 The ArjunBrowser Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_PQC_SESSIONS_DB_SCHEMA_VERSION_H_
#define COMPONENTS_PQC_SESSIONS_DB_SCHEMA_VERSION_H_

namespace pqc_sessions {

// Current schema version for the PQC session database.
// Increment this when making schema changes that require migration.
constexpr int kCurrentSchemaVersion = 1;

// Minimum schema version that is backward-compatible.
constexpr int kMinCompatibleVersion = 1;

// Database filename
constexpr char kDatabaseFileName[] = "pqc_sessions.db";

} // namespace pqc_sessions

#endif // COMPONENTS_PQC_SESSIONS_DB_SCHEMA_VERSION_H_
