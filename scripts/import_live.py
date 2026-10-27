#!/usr/bin/env python3
"""Import live sing-box client configs into a renderer config root.

This is a one-off migration helper. It reads a directory of per-client JSON
configs (the kind served by the previous subscription endpoint) and writes the
private config tree consumed by sb-render:

    <root>/templates/base.json.tmpl
    <root>/modes/tun.json
    <root>/modes/tproxy.json
    <root>/users/<name>.json

The generated tree contains real UUIDs and must never be committed. Only counts
and output paths are printed; UUIDs and config bodies stay out of stdout and
stderr (messages redact any UUID-shaped filename fragment).

Usage:
    import-live.sh --from <dir-of-live-client-json> --to <config-root> \
        [--owner general]

Standard library only.
"""

import argparse
import copy
import json
import re
import sys
from pathlib import Path
from typing import NoReturn

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
UUID_PLACEHOLDER = "{{.UUID}}"
PREFIX_HOOK = {"$hook": "prefix"}


class ImportFailure(Exception):
    """A user-facing import error; message is safe to print."""


def redact(text: str) -> str:
    """Hide UUID-shaped fragments (filenames may embed one)."""
    return UUID_RE.sub("<uuid>", text)


def fail(message: str) -> NoReturn:
    raise ImportFailure(message)


def iter_strings(value):
    """Yield every string nested inside a JSON value."""
    if isinstance(value, dict):
        for nested in value.values():
            yield from iter_strings(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from iter_strings(nested)
    elif isinstance(value, str):
        yield value


def first_inbound(doc: dict, inbound_type: str):
    inbounds = doc.get("inbounds")
    if not isinstance(inbounds, list):
        return None
    for inbound in inbounds:
        if isinstance(inbound, dict) and inbound.get("type") == inbound_type:
            return inbound
    return None


def find_uuid(doc: dict):
    """Return the first UUID string in any inbound or outbound."""
    for section in ("inbounds", "outbounds"):
        for value in iter_strings(doc.get(section)):
            match = UUID_RE.search(value)
            if match:
                return match.group(0)
    return None


def is_mixed_resolve_rule(rule) -> bool:
    """True for the `action: resolve` rule that targets the mixed inbound."""
    if not isinstance(rule, dict) or rule.get("action") != "resolve":
        return False
    inbound = rule.get("inbound")
    if inbound == "mixed-in":
        return True
    return isinstance(inbound, list) and "mixed-in" in inbound


def find_resolve_rule(doc: dict):
    route = doc.get("route")
    if not isinstance(route, dict):
        return None
    rules = route.get("rules")
    if not isinstance(rules, list):
        return None
    for rule in rules:
        if is_mixed_resolve_rule(rule):
            return rule
    return None


def derive_name(path: Path) -> str:
    name = path.stem.split("-", 1)[0]
    if not NAME_RE.fullmatch(name):
        fail(
            f"invalid username {name!r} derived from {redact(path.name)!r}; "
            "expected ^[A-Za-z0-9][A-Za-z0-9._-]*$"
        )
    return name


def load_inputs(source: Path):
    if not source.exists():
        fail(f"input directory does not exist: {source}")
    if not source.is_dir():
        fail(f"input path is not a directory: {source}")

    files = sorted(
        p for p in source.glob("*.json") if p.is_file() and not p.name.startswith(".")
    )
    if not files:
        fail(f"no *.json config files found in {source}")

    configs = []
    seen = {}
    for path in files:
        label = redact(path.name)
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            fail(f"cannot read JSON config {label!r}: {exc}")
        if not isinstance(doc, dict):
            fail(f"config {label!r} is not a JSON object")

        name = derive_name(path)
        if name in seen:
            fail(
                f"duplicate username {name!r} from {label!r} "
                f"(already imported from {seen[name]!r})"
            )
        seen[name] = label
        configs.append({"name": name, "label": label, "doc": doc})

    return configs


def require_inbound(config: dict, inbound_type: str):
    inbound = first_inbound(config["doc"], inbound_type)
    if inbound is None:
        fail(
            f"config {config['label']!r} ({config['name']}) has no "
            f'"type": "{inbound_type}" inbound'
        )
    return inbound


def build_base(representative: dict) -> str:
    doc = copy.deepcopy(representative["doc"])
    doc["inbounds"] = []

    route = doc.get("route")
    if not isinstance(route, dict):
        route = {}
        doc["route"] = route
    rules = route.get("rules")
    if not isinstance(rules, list):
        rules = []
    route["rules"] = [copy.deepcopy(PREFIX_HOOK)] + [
        rule for rule in rules if not is_mixed_resolve_rule(rule)
    ]

    text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    return UUID_RE.sub(UUID_PLACEHOLDER, text)


def build_modes(
    tun_inbound: dict, mixed_inbound: dict, tproxy_inbound: dict, resolve_rule
):
    prefix = []
    if resolve_rule is not None:
        rule = copy.deepcopy(resolve_rule)
        # The hook is spliced into the shared top-level rule list, so the
        # mixed-in selector is dropped; matches examples/modes/tun.json.
        rule.pop("inbound", None)
        prefix.append(rule)

    tun_mode = {
        "inbounds": [copy.deepcopy(tun_inbound), copy.deepcopy(mixed_inbound)],
        "route": {"rules": {"prefix": prefix}},
    }
    tproxy_mode = {"inbounds": [copy.deepcopy(tproxy_inbound)]}
    return tun_mode, tproxy_mode


def confined_path(root: Path, *parts: str) -> Path:
    dest = root.joinpath(*parts)
    if not dest.resolve().is_relative_to(root.resolve()):
        fail(f"refusing to write outside config root: {dest}")
    return dest


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    print(f"wrote {path}")


def write_json(path: Path, value) -> None:
    write_text(path, json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def run(argv) -> int:
    parser = argparse.ArgumentParser(
        prog="import-live.sh",
        description=(
            "Import live sing-box client configs into a sb-render config root. "
            "Writes real UUIDs to disk; never commit the output."
        ),
    )
    parser.add_argument(
        "--from",
        dest="source",
        required=True,
        metavar="DIR",
        help="directory containing the live per-client *.json configs",
    )
    parser.add_argument(
        "--to",
        dest="dest",
        required=True,
        metavar="CONFIG_ROOT",
        help="config root to write templates/, modes/, and users/ into",
    )
    parser.add_argument(
        "--owner",
        default="general",
        metavar="NAME",
        help="username allowed to request tproxy (default: general)",
    )
    args = parser.parse_args(argv)

    if not NAME_RE.fullmatch(args.owner):
        fail(
            f"invalid --owner name {args.owner!r}; "
            "expected ^[A-Za-z0-9][A-Za-z0-9._-]*$"
        )

    source = Path(args.source).expanduser()
    destination = Path(args.dest).expanduser()
    if destination.exists() and not destination.is_dir():
        fail(f"output path exists and is not a directory: {destination}")

    configs = load_inputs(source)

    tun_inbounds = {}
    mixed_inbounds = {}
    uuids = {}
    for config in configs:
        name = config["name"]
        tun_inbounds[name] = require_inbound(config, "tun")
        mixed_inbounds[name] = require_inbound(config, "mixed")
        uuid = find_uuid(config["doc"])
        if uuid is None:
            fail(
                f"config {config['label']!r} ({name}) has no UUID "
                "in any inbound or outbound"
            )
        uuids[name] = uuid

    # tproxy must exist somewhere in the input set; we never synthesize one.
    representative = next(
        (config for config in configs if config["name"] == args.owner),
        configs[0],
    )
    tproxy_inbound: dict | None = None
    for config in [representative] + configs:
        tproxy_inbound = first_inbound(config["doc"], "tproxy")
        if tproxy_inbound is not None:
            break
    if tproxy_inbound is None:
        fail(
            "no tproxy inbound found in any input config; add one to the live "
            "config before importing (the importer will not invent it)"
        )

    resolve_rule = find_resolve_rule(representative["doc"])
    if resolve_rule is None:
        print(
            "warning: no mixed-in resolve rule found; "
            "the tun prefix hook will be empty",
            file=sys.stderr,
        )

    if args.owner not in uuids:
        print(
            f"warning: owner {args.owner!r} is not among the imported users; "
            "no user will be allowed to request tproxy",
            file=sys.stderr,
        )

    destination.mkdir(parents=True, exist_ok=True)

    base = build_base(representative)
    tun_mode, tproxy_mode = build_modes(
        tun_inbounds[representative["name"]],
        mixed_inbounds[representative["name"]],
        tproxy_inbound,
        resolve_rule,
    )

    write_text(confined_path(destination, "templates", "base.json.tmpl"), base)
    write_json(confined_path(destination, "modes", "tun.json"), tun_mode)
    write_json(confined_path(destination, "modes", "tproxy.json"), tproxy_mode)

    for config in configs:
        name = config["name"]
        user = {"uuid": uuids[name]}
        if name == args.owner:
            user["allow_tproxy"] = True
        write_json(confined_path(destination, "users", f"{name}.json"), user)

    print(f"imported {len(configs)} users into {destination / 'users'}")
    return 0


def main() -> int:
    try:
        return run(sys.argv[1:])
    except ImportFailure as exc:
        print(f"import-live: error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("import-live: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
