# openom

**openom** is a local-first, end-to-end-encrypted family tree. One Rust core runs everywhere — a desktop
and mobile app (Tauri) and a buildless web app — and syncs through a zero-knowledge server that only ever
stores opaque encrypted blobs. Your genealogy, your keys, your device.

*openom* is *open* + *om* — ኦም (*om*) is "tree" in Tigrinya, a language of the Tigray Region of Ethiopia
and of Eritrea.

- [Concepts](concepts.md) — the trust model and how a tree's state is represented.
- [Architecture](architecture.md) — the Rust core, its seams, and the crates.
- [Local development](getting-started.md) — set up and run the browser, API, services, and native shell.

!!! note
    openom is a prototype. The architecture, crypto, sync, and sharing are built and tested; persistence
    and UX polish are ongoing.
