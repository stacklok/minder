-- SPDX-FileCopyrightText: Copyright 2024 The Minder Authors
-- SPDX-License-Identifier: Apache-2.0

BEGIN;

ALTER TABLE session_store DROP COLUMN IF EXISTS provider_config;

COMMIT;
