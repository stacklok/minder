-- Copyright 2024 Stacklok, Inc
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--      http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

BEGIN;

ALTER TABLE provider_github_app_installations
    DROP CONSTRAINT provider_github_app_installations_project_id_fkey;

ALTER TABLE provider_github_app_installations DROP COLUMN project_id;

ALTER TABLE provider_github_app_installations DROP COLUMN enrollment_nonce;

ALTER TABLE provider_access_tokens DROP COLUMN enrollment_nonce;

COMMIT;