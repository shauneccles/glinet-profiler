# Rich-Schema: Registry Entries You Can Code Against — Design Spec

**Date:** 2026-06-29
**Status:** Design — awaiting review
**Repos:** `glinet-profiler` (distiller) + `glinet-registry` (pairing, display, OpenRPC)

## 1. Goal

From a **single registry entry**, a developer can write a gli4py endpoint with high
confidence it will work first try — without guessing the request params or the response
shape.

Concretely, an entry should answer:
1. Does it exist and work? — *already have* (`status: available` from a real probe).
2. What do I send? — the request fields, with formats.
3. What comes back? — the response fields, with **formats and example values**, not just type names.

## 2. Problem

A method entry today carries `status`, `risk`, `params` (names only, often empty),
`schema` (type-erased: `{"period_seconds": "int"}`), and `covered_by`. Two gaps force guessing:

- **Writes — what to send.** `params` is frequently empty: the names live in compiled
  validator/handler bytecode we cannot fully recover (the router's `-32602` error names no
  field; handlers are stripped bytecode). Confirmed dead end.
- **Reads & writes — the real shape.** `"int"` does not tell you `period_seconds` is `86400`
  (one day); `"str"` does not tell you `band` is one of `"2g"/"5g"/"6g"` or that a field holds
  an IPv4. Type names are too thin to code against confidently.

`--keep-data` already proves the real values are available locally — but the raw values cannot
go into a public registry (they are the submitter's SSIDs, client hostnames, IPs, topology).

## 3. Solution overview

Two parts, each independently testable:

- **A. Rich-schema distiller (launcher).** At sanitize time, each probed method's response
  value is distilled into a publishable `signature`: structure + formats + *safe* example
  scalars. Raw values never leave the user's machine.
- **B. get/set pairing (registry).** A `set_*` method's request shape ≈ its `get_*` sibling's
  `signature`. Pair them so one captured read documents *both* directions, and surface the
  `signature` + pairing in the browse site and OpenRPC export.

### Privacy boundary (non-negotiable)

The distiller runs **in the launcher, on the user's machine, at sanitize time**. The published
profile carries the distilled `signature` only — never raw values. Example data is scrubbed to
the **Balanced** bar *before* anything is written to disk for submission. The registry never
receives raw values (it cannot — the profile has none), so the distiller *must* live in the
launcher.

## 4. Part A — the distiller (`glinet-profiler`)

### 4.1 Placement

New module `enumerator/signature.py` exposing `signature_of(value: object) -> object`. Called in
`enumerator/probe.py::_report` next to `schema_of`/`redact`, on the **raw** response value (full
fidelity, never published). The result is stored on `MethodReport.signature`.
`sanitize.project_report` publishes `signature` and continues to drop `value`.

### 4.2 Balanced labeling rules

`signature_of` deep-walks the value. First matching rule wins:

| Node | Result |
|------|--------|
| `dict` | `{k: signature_of(v)}` — but if key `k` is **personal** and `v` is a string, emit `"<string>"` without recursing |
| `list` | `[signature_of(first)]` if non-empty, else `[]` |
| number / bool / `null` | **kept verbatim** (`86400`, `false`, `null`) — these are the contract, no PII |
| string, key is **secret** | `"<secret>"` |
| string matching MAC | `"<mac>"` |
| string matching IPv4 / IPv6 | `"<ipv4>"` / `"<ipv6>"` |
| string matching ISO-8601 / unix-ts | `"<datetime>"` |
| string, key is **personal** | `"<string>"` |
| string, **enum-like** (`^[A-Za-z0-9._:-]{1,24}$`, no spaces) | **kept verbatim** (`"5g"`, `"ap"`, `"connected"`) |
| string, else (long / spaced / free text) | `"<string>"` |

- **secret keys:** reuse `redact._SECRET_TOKENS` (password/key/sn/serial/token/hash/salt/cert/…).
- **personal keys:** `ssid`, `name`, `hostname`, `host`, `comment`, `description`, `desc`,
  `note`, `label`, `path`, `url`, `email`, `domain`, `user`, `username`, `server`, `endpoint`,
  `peer`, `address`, `addr` (whole-key or `_`-boundary, same matcher style as `_key_is_secret`).
  Treated as a tunable list, not a closed set.
- Labels are reserved sentinels in angle brackets; a real value already in that form is treated
  as a string and re-labeled, so sentinels never collide with data.

**Rationale.** Numbers, booleans, and short enums are the API contract and carry no PII;
identifiers and free text are replaced with a *format label* so the developer learns the
type/format without the submitter's data.

**Accepted residual risk.** A one-word SSID (or similar) under a non-personal key reads as an
enum and is kept. This is the Balanced trade-off chosen deliberately; the personal-key list plus
the MAC/IP/datetime value patterns catch the common leaks.

### 4.3 Example

Raw (local, never published) → published `signature`:

```
{ ssid: "ShaunsHouse", band: "5g", channel: 36, hidden: false,    →   { ssid: "<string>", band: "5g", channel: 36, hidden: false,
  uptime: 81234, gateway: "192.168.8.1",                              uptime: 81234, gateway: "<ipv4>",
  clients: [ { mac:"94:83:..", ip:"192.168.8.45",                     clients: [ { mac:"<mac>", ip:"<ipv4>",
               name:"Shaun-iPhone", band:"5g" } ] }                                name:"<string>", band:"5g" } ] }
```

The developer learns: `band` is an enum (`"5g"` seen), `channel`/`uptime` are ints,
`hidden` is bool, `gateway` is an IPv4, `clients` is a list of `{mac, ip, name, band}`. Enough to
type a wrapper. Zero of the submitter's config is published.

### 4.4 Data-model change

`MethodReport` gains `signature: object | None`. **`signature` replaces the type-erased
`schema`** in published profiles — it is a strict superset (base type is implied by the
example or label). Methods with no captured value (discovered writes, errors) get
`signature: null`; their request shape comes from get/set pairing (§5). The registry is
re-ingested (it currently holds one device, so no migration concern).

## 5. Part B — get/set pairing (`glinet-registry`)

### 5.1 Heuristic

For a write `<verb>_<noun>` (verb ∈ set/add/update/create/del/remove/clear), look in the **same
service** for a read whose noun matches, in priority order:
`get_<noun>`, `get_<noun>_list`, `get_<noun>_config`, `get_<noun>_info`. The first hit's
`signature` is the write's **likely request shape**. No match → no inference (leave params as-is).

### 5.2 Surfacing

- **OpenRPC (`to_openrpc`):** every method emits its `signature` as the result `schema` + an
  `examples` entry. A paired write additionally gets `params` derived from the read's signature,
  tagged `x-inferred-from: "<service>.get_<noun>"` so consumers know it is inferred, not observed.
- **Browse site:** render the `signature` (formats + examples) in place of the bare type list;
  on a write, add a "Request shape (inferred from `get_<noun>`)" block showing the paired read's
  signature.
- **Manifest:** unchanged. Pairing is derived at export/render time, not stored.

## 6. Affected files

**glinet-profiler**
- `src/glinet_profiler/enumerator/signature.py` — new: `signature_of` + format/key helpers.
- `src/glinet_profiler/enumerator/redact.py` — export shared helpers (`_key_is_secret`,
  MAC/IP/datetime patterns) for reuse; no behavior change to `redact`.
- `src/glinet_profiler/enumerator/models.py` — `MethodReport.signature` field.
- `src/glinet_profiler/enumerator/probe.py` — compute `signature` in `_report`.
- `src/glinet_profiler/sanitize.py` — publish `signature`, drop `schema`/`value`.
- `tests/test_enum_signature.py` (new), updates to `test_sanitize.py`, `test_enum_probe.py`.

**glinet-registry**
- `tools/registry_lib.py` — `to_openrpc` reads `signature`, adds `examples` + get/set pairing
  (`_pair_write`, `x-inferred-from`).
- `site/app.js`, `site/style.css` — render `signature` + the inferred request block.
- `tests/test_registry_lib.py` — pairing + examples; re-ingest the MT6000.

## 7. Future (explicitly not v1)

- **Cross-device enum union.** For the same model+firmware across submissions, union the kept
  enum values per field → `band: "2g" | "5g" | "6g"`. Needs the v1 `signature` field plus a
  registry aggregation step. Designed-for, not built.
- **Required/optional param flags.** Would require observing which fields a write rejects;
  out of scope.

## 8. Testing strategy

- **`signature_of` unit tests** — one per rule: numbers/bools/null kept; MAC/IPv4/IPv6/datetime/
  secret labeled; personal-keyed string labeled; enum-like kept; long/spaced string labeled;
  nested dict + list; the documented SSID-as-enum edge case.
- **Sanitize** — `signature` published, `value`/`schema` dropped; property test: no IPv4/MAC/
  secret survives in the published signature for the MT6000 keep-data fixture.
- **Registry** — `set_config` pairs to `get_config`; unpaired write infers nothing; OpenRPC
  carries `examples` + `x-inferred-from`; browse renders a signature.
- **End-to-end** — distill the existing MT6000 capture; assert the published signature is
  PII-free and preserves enums/numbers (a concrete regression guard).

## 9. Open question resolved

Labeling aggressiveness = **Balanced** (keep enums + numbers/bools; label identifiers and
personal-keyed strings). Chosen 2026-06-29.
