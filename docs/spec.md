# sb-render specification

This document is the precise contract for `sb-render`: the on-disk config
format, the template and `$hook` semantics, the HTTP surface, the trust model,
and the migration/deployment expectations. It describes the implemented
behavior, not an aspiration.

## Scope

`sb-render` is a small HTTP renderer for per-user sing-box client
configurations. It reads three kinds of files from a config root, merges them,
and returns JSON.

It does not implement, and will not implement:

- user authentication or authorization beyond checking `X-Auth-User`
- a database, panel, admin UI, traffic accounting, or subscription expiry
- automatic certificates, ACME, or TLS termination
- template inheritance, partials, plugins, or a generic config DSL
- a sing-box runtime or a `sing-box check` on every request

TLS, Basic Auth, and rate limiting belong to nginx. Certificate issuance belongs
to the operator's existing tooling.

## Config root layout

The `--config` directory is the root passed to `os.OpenRoot`. It must exist and
be a directory; the process refuses to start otherwise.

```text
<config-root>/
  users/
    <name>.json
  modes/
    <mode>.json
  templates/
    base.json.tmpl
    owner.json.tmpl
```

`templates/base.json.tmpl` is the default template and the friend base.
`templates/owner.json.tmpl` is the owner base and adds the top-level
`http_clients` array. Any other profile file that passes the name pattern may
exist; the server does not special-case `owner`. The examples use `owner` for the
owner because the owner's current client config carries `http_clients`.

Every request re-reads the user file, the selected template, and the selected
mode. There is no in-process config cache, so edits take effect on the next
request.

## Names and path confinement

User names come from the `X-Auth-User` request header (trimmed of surrounding
whitespace). Mode names come from the `mode` query parameter. Template profile
names come from the user's `template` field. All three must match:

```text
^[A-Za-z0-9][A-Za-z0-9._-]*$
```

The pattern forbids path separators, a leading dot, and `..`. On top of that,
every file is opened through `*os.Root` (`os.OpenRoot`), so absolute paths,
parent-directory components, and symlinks that resolve outside the root are
rejected by the Go runtime. There is no fallback path.

Names that fail the pattern produce `ErrInvalidName` and an HTTP 400. The only
accepted mode values are `tun` and `tproxy`. Any other value in the `mode` query
or in a user's `modes` list is also `ErrInvalidName`.

A template profile that fails the pattern produces `ErrInvalidName` and an HTTP 400. A valid template name whose file does not exist produces
`ErrUnknownTemplate` and an HTTP 404.

Each file is read with a 4 MiB cap (4,194,304 bytes). A larger file produces
`ErrInvalidConfig` and an HTTP 500.

## `users/<name>.json`

A JSON object describing one client identity and its mode permissions.

```json
{
  "template": "owner",
  "uuid": "00000000-0000-0000-0000-000000000001",
  "modes": ["tproxy", "tun"],
  "default": "tun"
}
```

| Field      | Type   | Required | Default    | Meaning                                                                                                                                         |
| ---------- | ------ | -------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `template` | string | no       | `base`     | Selects `templates/<template>.json.tmpl`. Empty means `base`. Must match the name pattern. A missing file is a 404.                             |
| `uuid`     | string | yes      | none       | Value substituted for `{{.UUID}}` in the template. Must be non-empty after trimming; it is not otherwise format-validated.                      |
| `modes`    | array  | no       | `["tun"]`  | Modes the user may request. An empty or missing list means `["tun"]`. Every entry must be `tun` or `tproxy`.                                    |
| `default`  | string | no       | `modes[0]` | Mode used when the request omits `mode`. Empty means the first entry in `modes`. It must be present in `modes`, otherwise the request is a 404. |

Additional fields are ignored by `encoding/json`.

Validation order for one render:

1. Load `users/<name>.json`. Missing file is 404, malformed JSON or an empty
   `uuid` is 500.
2. Resolve the template profile. An empty `template` becomes `base`; an invalid
   name is 400; a missing file is 404.
3. Resolve the effective mode list. An empty list becomes `["tun"]`. Every entry
   must be a known mode, otherwise 400.
4. Resolve the effective default. An empty `default` becomes `modes[0]`. A
   default that is not in the effective list is 404.
5. Apply the requested `mode`. An empty value uses the effective default. An
   unknown mode string is 400. A known mode that is not in the effective list is 403. A missing mode file is 404.

Step 2 runs before mode validation, so a missing template is reported as 404 even
when the user file also has a bad mode list.

`http_clients` is not a user field. It is a valid top-level field in the current
sing-box schema
(<https://sing-box.sagernet.org/schema.json>) and belongs only to the owner
profile, where it lives in `templates/owner.json.tmpl`. The renderer passes it
through unchanged and never adds it to a friend config.

Examples use placeholder UUIDs. Real user files contain secrets and must stay
out of git; `config/` is gitignored.

## `modes/<mode>.json`

A JSON object describing the parts of the configuration that vary by inbound
mode.

```json
{
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in"
    }
  ],
  "route": {
    "rules": {
      "prefix": [
        {
          "action": "resolve",
          "server": "local"
        }
      ]
    }
  }
}
```

| Field         | Type   | Required | Meaning                                                                                                                                                                                    |
| ------------- | ------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `inbounds`    | array  | yes      | Values installed verbatim as the top-level `inbounds` array. A missing or `null` value is treated as `[]`, which yields a config with no inbounds; always include the field in real modes. |
| `route.rules` | object | no       | Maps a hook name to an array of rule values. Each array replaces the matching `{"$hook":"<name>"}` marker.                                                                                 |

The mode's `route.rules` mapping is not emitted as JSON. It is only used to
expand markers in the template. A mode may supply any number of hook names.

Inserted rule values are copied verbatim; the renderer does not validate that
they look like sing-box rules. Invalid rules will be returned to the client and
only fail later in `sing-box check`.

Mode file names are validated with the same pattern as user names. A missing
mode file produces `ErrUnknownMode` and an HTTP 404.

## `templates/<profile>.json.tmpl`

The template file is `templates/<profile>.json.tmpl`. `profile` comes from the
user's `template` field. An empty field selects `base`, which reads
`templates/base.json.tmpl`. The profile name must match
`^[A-Za-z0-9][A-Za-z0-9._-]*$`. An invalid name is an HTTP 400; a valid name
whose file is missing is an HTTP 404.

The two example profiles have different jobs:

- `templates/base.json.tmpl` is the friend and default base. It has no
  `http_clients`.
- `templates/owner.json.tmpl` is the owner base. It is the same client config
  plus a top-level `http_clients` array. `http_clients` is valid in the current
  sing-box schema (<https://sing-box.sagernet.org/schema.json>) and belongs only
  to the owner profile. Friends stay on `base` so they do not inherit it.

The template is parsed with the standard library `text/template` using
`Option("missingkey=error")`. The execution data contains exactly two keys:

| Key     | Value                            |
| ------- | -------------------------------- |
| `.UUID` | `users/<name>.json` `uuid`       |
| `.Name` | the user name from `X-Auth-User` |

Rules for authoring:

- The template must render to a JSON object. Scalars, arrays, `null`, and
  invalid JSON are rejected with a render error.
- Put `{{.UUID}}` and `{{.Name}}` inside quoted JSON strings. The template stage
  does not JSON-escape values; a value containing `"` or a newline breaks the
  document and produces a 500.
- The top level must contain `"inbounds": []`. The renderer overwrites this key
  with the selected mode's `inbounds`, so the placeholder value is not used.
- There is no inheritance, include, partial, or layout feature. Each profile is
  one complete document.
- The only template actions supported are those provided by `text/template`.
  No custom functions are registered.
- The renderer never validates `http_clients` or any other sing-box field. A
  template with an unknown field still renders and only fails in `sing-box
check`.

A minimal skeleton:

```json
{
  "log": { "level": "info" },
  "inbounds": [],
  "outbounds": [
    {
      "type": "vless",
      "tag": "proxy",
      "server": "proxy.example.com",
      "server_port": 443,
      "uuid": "{{.UUID}}",
      "tls": {
        "enabled": true,
        "server_name": "{{.Name}}.example.com"
      }
    }
  ],
  "route": {
    "rules": [{ "$hook": "prefix" }, { "action": "sniff" }],
    "final": "proxy"
  }
}
```

The owner profile is the same shape with a top-level block such as:

```json
{
  "http_clients": [
    { "tag": "default", "engine": "go", "version": 2, "detour": "proxy" }
  ]
}
```

## `$hook` semantics

A hook marker is a JSON object whose only meaningful key is `$hook`, with a
string value, for example `{"$hook":"prefix"}`. Markers are recognized only as
elements of the top-level `route.rules` array.

Expansion rules:

1. The renderer walks `route.rules` in order.
2. For each element that is an object containing `$hook`:
   - The value must be a string. Anything else is an error.
   - If `modes/<mode>.json` has `route.rules.<name>` as an array, the marker is
     replaced in place by the elements of that array, preserving their order.
   - If the mode does not define that hook, the marker is removed and nothing
     is inserted. This lets a shared template carry optional slots.
3. Non-marker elements are copied unchanged.
4. If the mode defines a hook that no marker consumed, rendering fails. The
   error names the first unused hook in sorted order. This catches typos such as
   `route.rules.prefx`.
5. Multiple markers may use the same hook; each is expanded. The hook is marked
   as used once.
6. Nested hooks are unsupported. The renderer does not descend into nested
   arrays or objects, so a `$hook` object below the top level is left untouched
   and would leak into the output. Do not place markers there.

Error conditions, all surfaced as HTTP 500 with the generic body
`{"error":"render failed"}`:

- the template is not valid `text/template`
- template execution fails, including a missing data key
- the rendered text is not valid JSON, or is not a JSON object
- `route` exists but is not an object
- `route.rules` exists but is not an array
- a top-level `route.rules` element is not an object
- a `$hook` value is not a string
- a mode hook has no matching marker
- the final document cannot be marshaled or is somehow invalid JSON

## HTTP contract

The server listens on loopback by default and is intended to be reached only by
nginx. It sets `gin.ReleaseMode`, includes `gin.Recovery()`, and emits one JSON
log line per request to stderr.

### Routes

| Method        | Path       | Auth                   | Behavior                                                                                                       |
| ------------- | ---------- | ---------------------- | -------------------------------------------------------------------------------------------------------------- |
| `GET`, `HEAD` | `/render`  | `X-Auth-User` required | Render the caller's config for `?mode=tun\|tproxy`. An empty mode uses the user's `default`.                   |
| `GET`, `HEAD` | `/healthz` | none                   | Liveness only. `GET` returns the three bytes `ok\n`; `HEAD` returns headers only. No config files are touched. |

Other paths and methods do not match a route and return 404. Method-not-allowed
handling is not enabled.

### Request handling

1. Read `X-Auth-User`, trim whitespace. Empty or missing means 401.
2. Load the user. Missing user is 404; malformed JSON or an empty `uuid` is 500.
3. Load the template selected by `template` (default `base`). Invalid profile
   name is 400; missing template is 404.
4. Resolve `modes` (default `["tun"]`) and `default` (default `modes[0]`). An
   unknown mode in `modes` is 400. A `default` outside `modes` is 404.
5. Read `?mode=`. Empty uses the resolved default. An unknown mode string is 400. A known mode that is not in `modes` is 403.
6. Load the selected mode file. Missing mode file is 404.
7. Render, then compute the ETag. Render failures are 500.

The `X-Auth-User` header is the only identity source. Query parameters never
select a different user.

### Response headers

Successful `/render` responses carry:

| Header                   | Value                                                                              |
| ------------------------ | ---------------------------------------------------------------------------------- |
| `Content-Type`           | `application/json; charset=utf-8`                                                  |
| `Cache-Control`          | `private, no-store`                                                                |
| `X-Content-Type-Options` | `nosniff`                                                                          |
| `ETag`                   | A quoted, full SHA-256 hex digest of the response body, for example `"9f86d0..."`. |

`/healthz` uses `Content-Type: text/plain; charset=utf-8` plus the same
`Cache-Control` and `X-Content-Type-Options` values.

`If-None-Match` is honored on `/render`. The parser accepts `*`, weak validators
of the form `W/"..."`, whitespace, and comma-separated lists. A match returns
304 with the same `ETag` and an empty body. Malformed values simply do not match.

`HEAD /render` performs the full render so its `ETag` matches the `GET`. A
successful HEAD sets `Content-Length` to the length the GET body would have and
writes no body.

### Status codes

| Status | Condition                                                                                                                         |
| ------ | --------------------------------------------------------------------------------------------------------------------------------- |
| 200    | Successful render, or `GET /healthz`.                                                                                             |
| 304    | `If-None-Match` matches the current ETag on `/render`.                                                                            |
| 400    | User name, template profile name, or mode string fails validation; or a user's `modes` list contains an unknown mode.             |
| 401    | `X-Auth-User` is missing or blank.                                                                                                |
| 403    | A known mode is requested but is not in the user's `modes` list.                                                                  |
| 404    | Unknown user, missing template file, missing mode file, or a `default` that is not in the user's effective `modes` list.          |
| 500    | Malformed user JSON, empty `uuid`, oversized file, template error, JSON error, hook error, or other configuration/render failure. |

Error responses on `GET` are JSON objects with a single generic message:

```json
{ "error": "unauthorized" }
```

The messages are `unauthorized`, `invalid request`, `mode not allowed`,
`not found`, and `render failed`. Filesystem paths and template contents are
never returned to the client. On `HEAD`, errors are status-only.

## `X-Auth-User` trust model

`sb-render` does no authentication. It trusts `X-Auth-User` completely. That is
safe only when both conditions hold:

1. The listener is reachable only by the authenticating proxy. The default
   `127.0.0.1` binding and the refusal to start on a non-loopback address
   without `--allow-public` enforce this by default.
2. The proxy always overwrites the header. nginx does this with
   `proxy_set_header X-Auth-User $remote_user;`, which replaces any
   client-supplied value.

Anyone who can reach the port can impersonate any user. Never expose the Go
service directly, never add `--allow-public` to a systemd unit, and never
publish a container port to the internet. nginx must terminate TLS; Basic Auth
is only base64-encoded on the wire.

## CLI

| Flag                 | Default          | Meaning                                                                 |
| -------------------- | ---------------- | ----------------------------------------------------------------------- |
| `--config`           | `./config`       | Config root containing `users/`, `modes/`, and `templates/`.            |
| `--listen`           | `127.0.0.1:8080` | Listen address. Non-loopback is refused unless `--allow-public` is set. |
| `--log-level`        | `info`           | `debug`, `info`, `warn`, or `error`, case-insensitive.                  |
| `--shutdown-timeout` | `10s`            | Graceful shutdown timeout. Must be positive.                            |
| `--allow-public`     | `false`          | Permit a non-loopback bind. Dangerous; see the trust model.             |

An empty host such as `:8080` is not loopback because it binds every interface.
`localhost`, `127.0.0.0/8`, and `::1` are treated as loopback. Positional
arguments are rejected. Logs are JSON on stderr. `SIGINT` and `SIGTERM` trigger
a graceful shutdown; a second signal exits immediately.

## Migration

`scripts/import-live.sh` builds a private config root from a directory of
existing per-client JSON configs:

```bash
./scripts/import-live.sh --from <dir-of-live-configs> --to ./config [--owner general] [--tproxy-json <file>]
```

It writes both profile templates, both modes, and one user file per client:

- `templates/base.json.tmpl` from the first non-owner config. Inbounds and the
  `mixed-in` resolve rule are removed, a `prefix` marker is inserted, and UUIDs
  become `{{.UUID}}`. This is the friend profile.
- `templates/owner.json.tmpl` from the owner config, with the same cleanup and
  the owner's top-level `http_clients` kept. This is the owner profile.
- `modes/tun.json` with the tun and mixed inbounds plus the resolve rule.
- `modes/tproxy.json` with only the tproxy inbound.
- `users/<name>.json` with each client's UUID. The owner (default `general`)
  gets `{"template": "owner", "modes": ["tproxy", "tun"], "default": "tun"}`.
  Every other user gets `{"uuid": ...}`, which defaults to `base` and `tun`.

Live client configs normally carry no tproxy inbound. `--tproxy-json <file>`
supplies one from a separate file. That file may be a bare tproxy inbound object
or an object whose `inbounds` array contains a tproxy inbound.

The generated tree contains real UUIDs and must never be committed; `config/` is
gitignored.

## Deployment

- `deploy/nginx.conf.example` terminates TLS, performs Basic Auth, and proxies
  `/sing-box.json` to `http://127.0.0.1:8080/render$is_args$args` with
  `X-Auth-User: $remote_user`. The `$is_args$args` suffix preserves the `mode`
  query, for example `?mode=tproxy`; an empty query falls back to the user's
  `default`.
- `deploy/sb-render.service.example` runs the binary as an unprivileged user
  with a hardened systemd unit and a loopback-only listener.
- `Dockerfile` builds a static binary and ships it in a scratch runtime, running
  as UID 10001. The container binds `0.0.0.0` internally and therefore passes
  `--allow-public`; that is only safe when the published port is restricted to
  host loopback or a private network and nginx still authenticates in front of
  it.

No real config is baked into the image or the repository. Mount `users/`,
`modes/`, and `templates/` read-only at runtime.
