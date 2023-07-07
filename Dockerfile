#
# Copyright 2023 Stacklok, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM golang:1.20.3@sha256:403f48633fb5ebd49f9a2b6ad6719f912df23dae44974a0c9445be331e72ff5e AS builder
ENV APP_ROOT=/opt/app-root
ENV GOPATH=$APP_ROOT

WORKDIR $APP_ROOT/src/
ADD go.mod go.sum $APP_ROOT/src/
RUN go mod download

# Add source code
ADD ./ $APP_ROOT/src/

RUN CGO_ENABLED=0 go build -trimpath -o mediator-server ./cmd/server

# Create a "nobody" non-root user for the next image by crafting an /etc/passwd
# file that the next image can copy in. This is necessary since the next image
# is based on scratch, which doesn't have adduser, cat, echo, or even sh.
RUN echo "nobody:x:65534:65534:Nobody:/:" > /etc_passwd

RUN mkdir -p /app

FROM scratch

COPY --chown=65534:65534 --from=builder /app /app

WORKDIR /app

# Copy database directory. This is needed for the migration sub-command to work.
COPY --chown=65534:65534 --from=builder /opt/app-root/src/database /app/database

# Copy policies directory. This is needed to parse policy schemas
COPY --chown=65534:65534 --from=builder /opt/app-root/src/config/policy_types /app/config/policy_types

COPY --from=builder /opt/app-root/src/mediator-server /usr/bin/mediator-server

# Copy the certs from the builder stage
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the /etc_passwd file we created in the builder stage into /etc/passwd in
# the target stage. This creates a new non-root user as a security best
# practice.
COPY --from=builder /etc_passwd /etc/passwd

USER nobody

# Set the binary as the entrypoint of the container
ENTRYPOINT ["/usr/bin/mediator-server"]
