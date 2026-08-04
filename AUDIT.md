# Clean Code and SRP Audit

## Summary

- **Highest-leverage split:** separate registry transport/presentation from catalog publication and persistence in `registry/src/main.rs`; this is deferred until route-level characterization exists.
- `cli/src/main.rs` is a 1,793-line command surface where registry I/O, installation persistence, package inspection, terminal presentation, and process termination change for different actors.
- `registry/src/security.rs` mixes two units with disjoint state and actors: compliance-owned WASM auditing and product/release-owned version lifecycle management. This split is safe and covered.
- The transform and sink modules are long, but each primarily serves one transform or external sink contract; length alone is not a reason to split them.
- Verification is now hermetic on Rust 1.85: formatting, strict Clippy, workspace tests/builds, WASM builds, and registry validation pass.

## Findings

| ID | Location | Category | Severity | Actors in conflict | Cost | Size | Behavior risk |
|---|---|---|---|---|---|---|---|
| MKT-SRP-1 | `registry/src/security.rs:1-853` | SRP | P2 | Compliance/security policy vs. product and release version lifecycle | A sandbox-policy change and a version-publication change edit the same module and test namespace despite sharing no state. `SecurityAuditor` owns only `WasmSecurityPolicy`; `VersionManager` owns only `HashMap<String, Vec<PublishedVersion>>`. Split into `security` and `versioning`. | S | Low |
| MKT-SRP-2 | `cli/src/main.rs:148-1144` | SRP | P1 | Registry API contract, local installation layout, release packaging, and CLI product presentation | Registry fallback changes, manifest migrations, publishing changes, and output redesign all collide in one file. Command functions share only `Cli`; registry functions touch HTTP, install functions touch filesystem state, and presentation touches neither durable state. Split toward `RegistrySource`, `InstallationStore`, and command-focused orchestration after adding HTTP/failure characterization. | L | High |
| MKT-SRP-3 | `registry/src/main.rs:126-429` | SRP | P1 | Ops runtime configuration, API consumers, registry publishers, and storage format | `main`, query handlers, authentication, multipart parsing, checksum policy, filesystem writes, and response construction change independently. A publication-policy change can break read routes or boot wiring. Split into router construction, catalog queries, and publication workflow after route tests exist. | L | High |
| MKT-SRP-4 | `registry/src/portal.rs:18-373` | SRP | P2 | Catalog product, identity, trust/reviews, and analytics | Transform methods use `transforms`; registration uses `users`; review methods use `transforms + config`; statistics use `stats`; only download recording bridges transform and user state. Split into `TransformCatalog`, `UserDirectory`, `ReviewService`, and `PortalMetrics` if the dormant portal is wired into production. | L | Medium |
| MKT-CC-1 | `cli/src/main.rs:236-247` | Error handling | P1 | Local installation state | Read and JSON parse failures are converted to an empty installation list. A corrupt manifest can make installed transforms appear absent and later overwrite recoverable state. Surface a typed error before changing this behavior. | S | Medium |
| MKT-CC-2 | `cli/src/main.rs:343-786` | Mixed abstraction / hidden side effects | P1 | Registry transport, integrity policy, filesystem persistence, and terminal UX | `cmd_install` downloads, verifies, creates directories, writes multiple files, updates a manifest, prints deployment guidance, and exits the process. Partial failures can leave disk state and manifest state inconsistent. | L | High |
| MKT-CC-3 | `cli/src/main.rs:1045-1099`, `registry/src/main.rs:492-506`, `registry/src/security.rs:188-198` | Duplication | P2 | CLI compatibility policy and registry version ordering | Three permissive semantic-version parsers can drift. Consolidate within each binary boundary; do not add a shared forwarding crate merely to remove a few lines. | S | Low |
| MKT-CC-4 | `registry/src/store.rs:19-82` | Error handling | P1 | Ops/storage reliability | Directory creation, file reads, and malformed persisted data can silently become an empty registry. A transient permission or corruption problem can look like valid empty state. Requires an explicit startup-failure policy decision. | M | High |
| MKT-SUP-1 | `registry/src/main.rs` -> `store.rs` | Layering | P2 | HTTP transport and persistence | HTTP handlers mutate `DataStore` maps and paths directly, so storage representation is part of route implementation. A storage migration requires transport edits. Introduce catalog operations only when route characterization can freeze status codes and payloads. | M | Medium |

## Ordered Refactor Sequence

1. **MKT-SRP-1:** move version lifecycle types and their tests from `security.rs` to `versioning.rs` without behavior changes.
2. **MKT-CC-3:** make registry version ordering use the extracted version policy, preserving the existing permissive parser.
3. Add route-level characterization for list, lookup, download, publish authorization, duplicate versions, malformed multipart data, and persistence failures.
4. **MKT-SRP-3 / MKT-SUP-1:** extract registry router construction and publication workflow, keeping all routes and serialized shapes frozen.
5. Add CLI HTTP and filesystem failure characterization with injectable process/output boundaries.
6. **MKT-SRP-2 / MKT-CC-2:** separate registry access and installation persistence from command presentation.
7. Address **MKT-SRP-4** only if the dormant portal becomes part of the served application.

## Deferred

- **MKT-CC-1:** changing corrupt-manifest handling would alter observable behavior; preserve it until a recovery/error contract is chosen and characterized.
- **MKT-CC-2:** install/publish extraction is unsafe without tests for HTTP failures, checksum mismatch, partial writes, manifest failure, and exit codes.
- **MKT-CC-4:** failing startup instead of returning an empty store is likely safer but is a correctness/policy change, not a refactor.
- `publish_transform` authentication and permissive CORS are security-policy decisions and remain outside this clean-code pass.
- The dormant portal and security auditor are not wired into registry routes; production integration is a feature change.

## Out of Scope

- Public CLI flags, command output contracts, registry routes, JSON fields, transform ABI exports, checksums, and registry data formats remain unchanged.
- No shared crate is introduced between the CLI and registry solely to deduplicate small version helpers; that would add release/build indirection without removing a meaningful actor.
- Transform and sink files over 150 lines remain intact where configuration, buffering, serialization, and delivery all serve the same external transform or sink contract and share the same state.
- Bugs discovered during audit are documented under **Deferred** rather than silently fixed during behavior-preserving refactoring.
