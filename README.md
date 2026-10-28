# sb-render

> **Personal project.** This is for my own use. It is not an open-source-standard
> project and comes with no support, stability, or security guarantees.

Per-user sing-box client config renderer, small enough to audit in one sitting.

`sb-render` reads a profile template, a per-mode fragment, and a per-user
identity, then returns a complete sing-box client configuration as JSON. nginx
sits in front and does TLS and Basic Auth. The renderer itself has no users
database, no panel, no traffic accounting, and no expiry logic.

## What this is

`sb-render` is a tiny per-user sing-box client config renderer that runs behind
nginx. It is **not a panel**. It does not track traffic, enforce expiry, store
users in a database, issue certificates, or provide any admin interface. Those
jobs stay with nginx, your certificate tooling, and you.

It exists to solve one problem: hand each client a valid sing-box config that
contains custom `outbounds`, `certificate` blocks, and routing rules, without
copying a 20 KB template once per user and without adopting a subscription
platform.

What it does:

- reads `users/<name>.json`, `modes/<mode>.json`, and
  `templates/<template>.json.tmpl`
- selects the template from the user's `template` field (`base` when empty)
- substitutes `{{.UUID}}` and `{{.Name}}`
- selects a mode from `?mode=` within the user's allowed `modes`
- installs the mode's `inbounds`
- expands `$hook` markers in `route.rules`
- returns normalized JSON with an ETag

What it does not do:

- Basic Auth, sessions, htpasswd, or any other authentication
- databases, panels, traffic stats, quotas, or subscription expiry
- ACME, automatic certificates, or TLS
- template inheritance, partials, plugins, or a config DSL
- a sing-box runtime or a `sing-box check` on every request

## How it works

```text
client
  |  HTTPS + Basic Auth
  v
nginx
  |  proxy_set_header X-Auth-User $remote_user
  v
sb-render  (127.0.0.1:8080)
  |  users/<name>.json
  |  modes/<mode>.json
  |  templates/<template>.json.tmpl
  v
JSON client config
```

nginx authenticates the client, overwrites `X-Auth-User` with the authenticated
username, and proxies the request to the loopback-only Go service. The service
trusts that header.

Profile and mode selection happen per request. The user file names a template
profile; an empty `template` means `base`, so the server reads
`templates/base.json.tmpl`. The user file also lists the modes the user may
request and the default mode. An empty `modes` list means `["tun"]`. An empty
`default` means the first entry in `modes`.

The request selects a mode with `?mode=tun|tproxy`. An omitted `mode` uses the
user's `default`. A known mode that is not in the user's `modes` is a 403. A mode
string that is not `tun` or `tproxy` is a 400. A missing template file or a
`default` outside `modes` is a 404.

Rendering is deterministic:

1. Load the user, choose the template profile, and read the profile template.
2. `text/template` substitutes the user's UUID and name into the template.
3. `encoding/json` parses the result.
4. The selected mode's `inbounds` array replaces the template's empty `inbounds`.
5. `$hook` markers in the top-level `route.rules` array are replaced by the
   mode's rule fragments.
6. The document is marshaled with stable indentation and returned.

Changing a template or a mode does not require a Go change. That is the point.

## Quickstart

Requirements: Go 1.27 or newer, `curl`, and `jq`. Run these commands from this
directory. The `examples/` tree is sanitized and safe to use.

Start the server:

```bash
go run ./cmd/sb-render --config examples --listen 127.0.0.1:8080
```

In a second terminal, request the default config for the example user `general`.
`general` uses the `owner` profile, so the response includes the owner's
`http_clients` block:

```bash
curl -sS -H 'X-Auth-User: general' http://127.0.0.1:8080/render | jq .
```

Request the opt-in `tproxy` mode. `general` lists both `tproxy` and `tun` in its
`modes` field and defaults to `tun`:

```bash
curl -sS -H 'X-Auth-User: general' 'http://127.0.0.1:8080/render?mode=tproxy' | jq .
```

Request `tproxy` as `alice`, whose `modes` list does not include it. The response
is 403:

```bash
curl -sS -H 'X-Auth-User: alice' 'http://127.0.0.1:8080/render?mode=tproxy' -o /dev/null -w '%{http_code}\n'  # 403
```

Health check:

```bash
curl -sS http://127.0.0.1:8080/healthz
```

`X-Auth-User` is a local testing convenience here. In production nginx supplies
it from Basic Auth and overwrites any value the client sends. Do not expose the
Go service directly and do not treat this header as authentication on its own.

Stop the server with Ctrl-C. `SIGINT` and `SIGTERM` trigger a graceful shutdown.

## Layout

```text
users/
  general.json        # template owner, uuid, modes [tproxy, tun], default tun
  alice.json          # uuid only; base template, tun only
modes/
  tun.json            # tun + mixed inbounds, prefix hook with a resolve rule
  tproxy.json         # tproxy inbound only
templates/
  base.json.tmpl      # friend/default base, no http_clients
  owner.json.tmpl     # owner base, adds http_clients
```

A user file is a small JSON object:

```json
{
  "template": "owner",
  "uuid": "00000000-0000-0000-0000-000000000001",
  "modes": ["tproxy", "tun"],
  "default": "tun"
}
```

Field rules:

- `template` is optional and defaults to `base`, which reads
  `templates/base.json.tmpl`. A non-empty value selects
  `templates/<template>.json.tmpl`. It must match
  `^[A-Za-z0-9][A-Za-z0-9._-]*$`.
- `uuid` is required and must be non-empty.
- `modes` is optional and defaults to `["tun"]`. Each entry must be `tun` or
  `tproxy`.
- `default` is optional and defaults to the first entry in `modes`. It must be
  one of the user's `modes`.

A missing template file or a `default` outside `modes` returns 404. A malformed
template name, an unknown mode string, or an unknown mode inside `modes` returns 400. A known mode that the user may not use returns 403. The full schema and the
complete status mapping are in [docs/spec.md](docs/spec.md).

A mode file provides the inbounds and, optionally, hook fragments:

```json
{
  "inbounds": [{ "type": "tun", "tag": "tun-in" }],
  "route": {
    "rules": {
      "prefix": [{ "action": "resolve", "server": "local" }]
    }
  }
}
```

`inbounds` is required in real mode files. `route.rules` is optional and maps a
hook name to an array of rules.

Templates are ordinary sing-box JSON with `"inbounds": []`, `{{.UUID}}` and
`{{.Name}}` placeholders inside quoted strings, and `$hook` marker objects in the
top-level `route.rules` array. `templates/base.json.tmpl` is the friend and
default base. `templates/owner.json.tmpl` is the owner base and adds a top-level
`http_clients` array. `http_clients` is a valid top-level field in the current
sing-box schema (<https://sing-box.sagernet.org/schema.json>) and belongs only to
the owner profile. Friend profiles use `base` and therefore do not inherit it.

## The `$hook` contract

The template owns the routing table. Modes contribute only the fragments that
differ.

```json
{
  "route": {
    "rules": [
      { "$hook": "prefix" },
      { "action": "sniff" },
      { "ip_is_private": true, "outbound": "direct" }
    ],
    "final": "proxy"
  }
}
```

The mode supplies the replacement:

```json
{
  "route": {
    "rules": {
      "prefix": [{ "action": "resolve", "server": "local" }]
    }
  }
}
```

The rendered rules become:

```json
[
  { "action": "resolve", "server": "local" },
  { "action": "sniff" },
  { "ip_is_private": true, "outbound": "direct" }
]
```

Rules:

- A marker is `{"$hook":"<name>"}` and is recognized only as an element of the
  top-level `route.rules` array.
- A matching `route.rules.<name>` array is spliced in place, in order. The
  surrounding rules keep their order.
- A marker with no matching mode hook is removed. Shared templates can therefore
  carry optional slots.
- A mode hook with no matching marker is an error. This catches typos such as
  `prefx`. The request returns 500 with a generic error body.
- The hook value must be a string.
- Multiple markers may name the same hook; each is expanded.
- Nested hooks are unsupported. Markers below the top level are not expanded
  and must not be used.

## Tun vs tproxy

The user's `modes` list decides which modes are available. There is no separate
permission flag.

`tun` is the common default. `modes/tun.json` in the examples provides a `tun`
inbound and a `mixed` inbound, plus a `prefix` hook that adds a resolve rule for
`local` DNS. Its output works for clients that route traffic through a TUN
device or a local mixed proxy port.

`tproxy` is opt-in with `?mode=tproxy`. A user can request it only when `tproxy`
appears in their `modes` list. The example `general` user has
`"modes": ["tproxy", "tun"]`, and `alice` has no `modes` field, which defaults to
`["tun"]`. The example `modes/tproxy.json` contains only the `tproxy` inbound and
no hook fragments, so the optional marker is removed. A request for a known mode
that is not in the user's list receives 403.

This split keeps a friend on a working `tun` config while letting the owner opt
into transparent proxy behavior when the network supports it. The owner also
uses the `owner` template, while friends use `base`.

## Importing existing configs

If you already serve per-client sing-box JSON files, import them once:

```bash
./scripts/import-live.sh --from <dir-of-live-configs> --to ./config [--owner general] [--tproxy-json <file>]
```

The importer reads the existing client configs and writes a private config root:

- `templates/base.json.tmpl` with `inbounds` removed, the `mixed-in` resolve
  rule removed, a `prefix` marker inserted, and UUIDs replaced by `{{.UUID}}`
- `templates/owner.json.tmpl` from the owner config, with the same cleanup plus
  the owner's top-level `http_clients`
- `modes/tun.json` with the tun and mixed inbounds plus the resolve rule
- `modes/tproxy.json` with only the tproxy inbound
- `users/<name>.json` with each client's UUID

The owner user gets `"template": "owner"`, `"modes": ["tproxy", "tun"]`, and
`"default": "tun"`. Friends get the `base` template, `["tun"]`, and `tun` as the
default. No user file carries a mode permission flag; the `modes` list is the
permission.

`--tproxy-json <file>` names a JSON file that carries the tproxy inbound. It may
contain a bare tproxy inbound object or an object whose `inbounds` array includes
one. Use it when the tproxy inbound is not present in the directory passed to
`--from`.

The generated `config/` is gitignored and contains real UUIDs. Never commit it.

## Deployment

Ready-to-copy examples live in the repository:

- [deploy/nginx.conf.example](deploy/nginx.conf.example): TLS, Basic Auth, and a
  proxy passing `X-Auth-User: $remote_user` to `127.0.0.1:8080/render`
- [deploy/sb-render.service.example](deploy/sb-render.service.example): hardened
  systemd unit for the loopback-only binary
- [Dockerfile](Dockerfile): static binary in a scratch runtime, non-root UID
  10001, read-only config mount

The important constraints:

1. nginx must overwrite `X-Auth-User`, not pass a client-supplied value through.
   `proxy_set_header X-Auth-User $remote_user;` replaces the header.
2. The Go service must stay loopback-only. Keep the default `--listen
127.0.0.1:8080`; never add `--allow-public` to a systemd unit.
3. The container binds `0.0.0.0` internally and therefore uses
   `--allow-public`. That is only safe when the published port is restricted to
   host loopback or a private network, for example `-p 127.0.0.1:8080:8080`,
   and nginx still does TLS and Basic Auth in front of it. Never publish the
   container port directly to the internet.
4. Mount `users/`, `modes/`, and `templates/` read-only at runtime. Never bake
   real config into an image.

A typical nginx location:

```nginx
location = /sing-box.json {
    proxy_pass http://127.0.0.1:8080/render$is_args$args;
    proxy_set_header X-Auth-User $remote_user;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

The client keeps using its existing subscription URL. Mode selection uses the
`mode` query parameter, for example `?mode=tproxy`, and `$is_args$args`
preserves the query when nginx proxies the request.

## CI/CD

GitHub Actions runs the test suite on `ubuntu-latest`. When the tests pass, the
container image is built natively per architecture: amd64 on `ubuntu-26.04` and
arm64 on `ubuntu-26.04-arm`. There is no QEMU emulation and no image is built on
the deployment host.

Each architecture build pushes its image by digest, then a merge job assembles
the digests into a multi-arch manifest. Images are published to
`ghcr.io/chaosoffire-org/sing-box-template-renderer`:

- pushes to `main` publish `latest` and a short-SHA tag
- `v*` tags publish semver tags
- pull requests only run tests; they do not push an image

Public repositories use standard GitHub-hosted runners, which are free and
unlimited for public repositories.

Production hosts only pull the published image. They do not build it locally.

## Security notes

- **`X-Auth-User` is a trust boundary.** The service does no authentication. It
  believes whatever username arrives in that header. Confidence is justified
  only because the listener is loopback-only and nginx overwrites the header.
- **Loopback by default.** `--listen 127.0.0.1:8080` is the default. A
  non-loopback address is refused unless `--allow-public` is passed. Empty hosts
  such as `:8080` count as non-loopback because they bind every interface.
- **Path confinement.** Files are opened through `os.OpenRoot`, so `..`,
  absolute paths, and symlinks escaping the config root are rejected. User and
  mode names must match `^[A-Za-z0-9][A-Za-z0-9._-]*$`; template profile names
  use the same pattern.
- **Bounded reads.** Each config file is limited to 4 MiB. Oversized files are a
  configuration error, not a memory risk.
- **No auth or database in Go.** There is no password store, no session, no
  database, and no admin endpoint. nginx owns TLS and Basic Auth.
- **No real config in git.** `config/`, `*.local.json`, and the generated
  import output are gitignored. `examples/` contains sanitized placeholders
  only.
- **Generic errors.** Client-facing errors never include filesystem paths or
  template contents. Details stay in server logs, and render errors are not
  echoed to clients at all.
- **TLS is mandatory in production.** Basic Auth is base64, not encryption.
  Terminate TLS in nginx and leave `Cache-Control: private, no-store` intact.

## Why not s-ui

s-ui and similar projects are full subscription platforms. Their JSON
subscription output does not preserve custom `outbounds`, `certificate` blocks,
or a per-client template layout. Reproducing those in a fork would mean carrying
a large upstream codebase and re-merging it on every release.

`sb-render` keeps only the renderer: three small file types, one HTTP endpoint,
and the standard library. It is less capable on purpose, and the parts it does
handle are easy to read and change when sing-box's config format moves.

## CLI flags

| Flag                 | Default          | Description                                                  |
| -------------------- | ---------------- | ------------------------------------------------------------ |
| `--config`           | `./config`       | Config root containing `users/`, `modes/`, and `templates/`. |
| `--listen`           | `127.0.0.1:8080` | Listen address. Non-loopback requires `--allow-public`.      |
| `--log-level`        | `info`           | One of `debug`, `info`, `warn`, `error`.                     |
| `--shutdown-timeout` | `10s`            | Graceful shutdown timeout. Must be positive.                 |
| `--allow-public`     | `false`          | Permit a non-loopback bind. Dangerous; keep nginx in front.  |

Logs are JSON on stderr. `--help` prints the same list. Positional arguments
are rejected.

## Routes and status codes

| Method        | Path       | Auth          | Description                                                                                                |
| ------------- | ---------- | ------------- | ---------------------------------------------------------------------------------------------------------- |
| `GET`, `HEAD` | `/render`  | `X-Auth-User` | Render the caller's config for `?mode=tun\|tproxy`. `HEAD` returns the same headers and ETag with no body. |
| `GET`, `HEAD` | `/healthz` | none          | Liveness only, returns `ok\n` for `GET`. Does not read config.                                             |

| Status | When                                                                                                            |
| ------ | --------------------------------------------------------------------------------------------------------------- |
| 200    | Successful render or health check.                                                                              |
| 304    | `If-None-Match` matches the current render ETag.                                                                |
| 400    | Invalid user name, invalid template profile name, unknown mode string, or unknown mode listed in the user file. |
| 401    | Missing or blank `X-Auth-User`.                                                                                 |
| 403    | A known mode requested by a user whose `modes` list does not include it.                                        |
| 404    | Unknown user, missing template file, missing mode file, or `default` not present in `modes`.                    |
| 500    | Template, JSON, hook, or other configuration/render failure.                                                    |

Successful `/render` responses set `Content-Type: application/json; charset=utf-8`,
`Cache-Control: private, no-store`, `X-Content-Type-Options: nosniff`, and a
quoted SHA-256 `ETag`. Errors on `GET` are `{"error":"..."}`; errors on `HEAD`
are status-only. See [docs/spec.md](docs/spec.md) for the complete contract.

## Verification

```bash
go test ./...
./scripts/verify.sh
gofmt -l .
go vet ./...
```

`scripts/verify.sh` runs the tests, builds the binary, starts it against
`examples/` on a free loopback port, and checks the full HTTP matrix: the
default render, `?mode=tproxy`, 403 for a user whose `modes` list excludes
tproxy, 404 for a missing user or template, 400 for an unknown mode, 401, 304,
`HEAD`, and `/healthz`. It validates JSON with `jq` and runs `sing-box check` on
the rendered configs when a `sing-box` binary is on `PATH`. A clean run ends with
`PASS all checks`.

`gofmt -l .` should print nothing.

## Publishing

The canonical repository is
<https://github.com/chaosoffire-org/sing-box-template-renderer>.

This directory is already a git repository with the work committed. The flow
below is for publishing a fresh copy, for example after exporting this
directory. The user runs the final push; replace `<name>` with the repository
name.

```bash
git init
git add .
git commit -m "Initial commit"
gh repo create <name> --public --source=. --push
```

`gh repo create` requires an authenticated GitHub CLI. If you keep the existing
history, skip `git init` and `git commit`; the checkout is ready to push.

Before publishing, confirm that no real config is tracked:

```bash
git status --short
git ls-files | grep -E '^(config|users|modes|templates)/' || true
```

The import output and all real user files must stay untracked.

## License

GPL-3.0. See [LICENSE](LICENSE).
