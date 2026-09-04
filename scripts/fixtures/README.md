# Release-validation fixtures

Hermetic inputs for `scripts/validate_registry_controls.sh`. They prove that
`scripts/validate_registry.py --mode release` binds an explicit
name/version/asset selection, expected release tag, and catalog digest to the
bytes staged for a release — in both directions — independent of the live
catalog's state and without any network access or published release.

## Artifacts (`artifacts/`)

Each file is a valid, minimal WebAssembly module: the 8-byte module header
followed by one custom section whose name makes the file unique.

| File | sha256 | Role |
|---|---|---|
| `fixture_released.wasm` | `a68332929568049a4fcfcfb52adc88c5a771dac1379589f8b33ecd93836796fb` | The artifact a released catalog entry must match |
| `fixture_pending.wasm` | `c0c711bfae114095e888badcc240abb0904be974ad7e49b3c0528bda002da830` | Staged for the pending control, so a `pending` entry fails for being pending on a shipped asset, not for a missing artifact |
| `fixture_unrelated.wasm` | `3bc8bf39cb6c4649140d9ea0c2e0ec674284177c7b90e299d699e48ce4de2b47` | The impostor: renamed to the expected asset name it must still fail, and staged unrenamed it must fail as unreferenced |

These bytes are the control, so they are versioned (`.gitignore` and
`.gitattributes` carry explicit exceptions) and must never be regenerated
casually. Verify with:

```bash
shasum -a 256 scripts/fixtures/artifacts/*.wasm   # sha256sum on Linux
```

This directory is a *byte source*, not a staging directory. Release mode also
rejects staged WASM artifacts that no catalog entry references, so the control
script composes a per-scenario staging directory under
`target/validate-registry-controls/` holding exactly the artifacts each catalog
claims — the same way a release job stages exactly what it is about to publish.

## Catalogs

Every fixture below is structurally valid except `catalog_duplicate_entry.json`,
which is a negative control in every mode. The release column names the staged
artifacts the control script uses for that scenario.

| File | Digests | Release |
|---|---|---|
| `catalog_released.json` | pass | pass — digest equals `fixture_released.wasm`, staged: `fixture_released.wasm` |
| `catalog_pending_absent.json` | fail — pending | **pass** — the pending entry names `fixture_absent.wasm`, which this release does not stage; staged: `fixture_released.wasm` |
| `catalog_pending_staged.json` | fail — pending | fail — `pending` for `fixture_pending.wasm`, which *is* staged |
| `catalog_wrong_digest.json` | pass — syntax is valid | fail — digest belongs to `fixture_unrelated.wasm` |
| `catalog_missing_artifact.json` | pass — syntax is valid | fail — a real digest claims `fixture_absent.wasm`, which was never built |
| `catalog_duplicate_entry.json` | fail — duplicate | fail — duplicate name/version pair |
| `catalog_released.json` + an extra staged module | — | fail — `fixture_unrelated.wasm` is staged but referenced by no entry |

Rows 4 and 5 are the blind spot artifact binding closes: syntax-only validation
cannot tell a correct digest from a plausible one. Rows 2, 3 and 7 are the
binding's second half: `pending` is honest only for a transform the release does
not ship, and nothing may ship without a catalog entry pinning its bytes.
