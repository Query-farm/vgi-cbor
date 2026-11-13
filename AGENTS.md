# Repository guidance

Use the latest stable published VGI SDK and RPC releases. Check the registry
when updating dependencies, update the manifests and lockfile together, and
resolve API or protocol changes. Prefer upgrading the worker to match the
current extension instead of downgrading the extension to preserve an old SDK.
Keep the Arrow dependency family on the SDK's supported major, using its latest
compatible release. Keep Cargo.lock committed for reproducible builds.

See CLAUDE.md for repository layout, coding conventions, and validation commands.
