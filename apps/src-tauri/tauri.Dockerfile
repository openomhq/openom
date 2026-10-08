# The Linux Tauri development image. It provides the WebKitGTK build dependencies used by desktop CI
# plus a localhost-only noVNC display for restricted hosts that cannot execute native build outputs.
# Docker Compose Watch syncs the workspace into /work so Tauri receives native filesystem events.
#
#   docker build -t openom-tauri-check -f apps/src-tauri/tauri.Dockerfile apps/src-tauri
#   docker run --rm -v "<repo>":/work -v openom-cargo-registry:/usr/local/cargo/registry \
#     -v openom-cargo-target-tauri:/tmp/target -w /work -e CARGO_TARGET_DIR=/tmp/target \
#     openom-tauri-check cargo check -p openom-tauri
FROM node:24.11.0-bookworm AS node

FROM rust:1.97.1-bookworm

COPY --from=node /usr/local/bin/ /usr/local/bin/
COPY --from=node /usr/local/lib/node_modules/ /usr/local/lib/node_modules/

RUN apt-get update && apt-get install -y --no-install-recommends \
      libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev \
      libssl-dev libgtk-3-dev pkg-config xvfb x11vnc openbox novnc websockify \
      dbus-x11 fonts-dejavu-core x11-utils \
  && npm install --global pnpm@11.20.0 \
  && rm -rf /var/lib/apt/lists/*

COPY dev-container.sh /usr/local/bin/openom-tauri-dev
RUN chmod +x /usr/local/bin/openom-tauri-dev

WORKDIR /work
