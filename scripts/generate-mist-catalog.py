#!/usr/bin/env python3
"""Generate the audited, deterministic Mist operation catalog.

This program deliberately generates data only. It never emits one MCP wrapper
per OpenAPI operation, and it fails closed if the locked source changes or an
operation cannot be represented by the catalog contract.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_SHA256 = "2c3d769ef188bbce1b9db7a0774b5a10812d0a5bc11960b768de47b66bb88bbf"
EXPECTED_INVENTORY_SHA256 = "d7aedc775485c00cde5160b96e9496652dde3e847f4fb4cdd2dc87ce2996f1e2"
UPSTREAM_COMMIT = "f3af90c696747d003b2d22fd15e7dcc94d288cac"
SOURCE_URL = "https://raw.githubusercontent.com/mistsys/mist_openapi/master/mist.openapi.json"
ALLOWED_METHODS = {"get", "post", "put", "patch", "delete"}
PATH_ITEM_METADATA = {"parameters", "summary", "description", "servers", "$ref"}
ALLOWED_REQUEST_MEDIA = {"application/json", "multipart/form-data"}
PATH_PARAMETER = re.compile(r"\{([A-Za-z][A-Za-z0-9_]*)\}")


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode()


def sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def tool_name(operation_id: str) -> str:
    """Use the frozen unicode_casefold_snake_case_v1 operation-name transform."""
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", operation_id):
        raise ValueError(f"unsafe operationId: {operation_id!r}")
    # These branded initialisms deliberately use mixed case. Normalizing them
    # before boundary detection keeps OAuth2, WiFi, IoT, and AOSCX one word.
    for original, normalized in (("OAuth2", "Oauth2"), ("OAUTH2", "Oauth2"), ("WiFi", "Wifi"), ("WIFI", "Wifi"), ("IoT", "Iot"), ("IOT", "Iot"), ("AOSCX", "Aoscx")):
        operation_id = operation_id.replace(original, normalized)
    words: list[str] = []
    word = ""
    for index, character in enumerate(operation_id):
        previous = operation_id[index - 1] if index else ""
        following = operation_id[index + 1] if index + 1 < len(operation_id) else ""
        boundary = (
            index > 0
            and character.isupper()
            and (previous.islower() or previous.isdigit() or (previous.isupper() and following.islower()))
        )
        if boundary:
            words.append(word.casefold())
            word = character
        else:
            word += character
    if word:
        words.append(word.casefold())
    name = "mist_" + "_".join(words)
    if not re.fullmatch(r"mist_[a-z0-9_]+", name):
        raise ValueError(f"derived tool name is unsafe: {name!r}")
    return name


def resolve_parameter(parameter: dict[str, Any], components: dict[str, Any]) -> dict[str, Any]:
    reference = parameter.get("$ref")
    if reference is None:
        return parameter
    prefix = "#/components/parameters/"
    if not isinstance(reference, str) or not reference.startswith(prefix):
        raise ValueError(f"unsupported parameter reference: {reference!r}")
    name = reference.removeprefix(prefix)
    resolved = components.get("parameters", {}).get(name)
    if not isinstance(resolved, dict):
        raise ValueError(f"unresolved parameter reference: {reference!r}")
    return resolved


def resolve_component_reference(value: dict[str, Any], components: dict[str, Any], collection: str, seen: set[str] | None = None) -> dict[str, Any]:
    """Resolve an exact local components reference and reject cycles/external refs."""
    reference = value.get("$ref")
    if reference is None:
        return value
    prefix = f"#/components/{collection}/"
    if not isinstance(reference, str) or not reference.startswith(prefix):
        raise ValueError(f"unsupported {collection} reference: {reference!r}")
    name = reference.removeprefix(prefix)
    seen = set() if seen is None else seen
    if name in seen:
        raise ValueError(f"cyclic {collection} reference: {reference!r}")
    resolved = components.get(collection, {}).get(name)
    if not isinstance(resolved, dict):
        raise ValueError(f"unresolved {collection} reference: {reference!r}")
    return resolve_component_reference(resolved, components, collection, seen | {name})


def validate_schema(schema: Any, components: dict[str, Any], stack: tuple[str, ...] = ()) -> None:
    """Ensure every schema reference is local, resolvable, and acyclic."""
    if isinstance(schema, list):
        for value in schema:
            validate_schema(value, components, stack)
        return
    if not isinstance(schema, dict):
        return
    reference = schema.get("$ref")
    if reference is not None:
        prefix = "#/components/schemas/"
        if not isinstance(reference, str) or not reference.startswith(prefix):
            raise ValueError(f"unsupported schema reference: {reference!r}")
        name = reference.removeprefix(prefix)
        if name in stack:
            raise ValueError(f"cyclic schema reference: {reference!r}")
        resolved = components.get("schemas", {}).get(name)
        if not isinstance(resolved, dict):
            raise ValueError(f"unresolved schema reference: {reference!r}")
        validate_schema(resolved, components, (*stack, name))
    for key, value in schema.items():
        if key != "$ref":
            validate_schema(value, components, stack)


def request_details(operation: dict[str, Any], components: dict[str, Any]) -> tuple[list[str], dict[str, Any], str]:
    content = operation.get("requestBody", {}).get("content", {})
    if not isinstance(content, dict):
        raise ValueError("requestBody.content must be an object")
    media = sorted(content)
    unsupported = set(media) - ALLOWED_REQUEST_MEDIA
    if unsupported:
        raise ValueError(f"unsupported request media types: {sorted(unsupported)}")
    schemas = {}
    for media_type, media_type_data in content.items():
        if not isinstance(media_type_data, dict) or not isinstance(media_type_data.get("schema"), dict):
            raise ValueError(f"missing request schema for {media_type}")
        schema = media_type_data["schema"]
        validate_schema(schema, components)
        schemas[media_type] = schema
    if not media:
        transport = "none"
    elif media == ["application/json"]:
        transport = "json"
    elif media == ["multipart/form-data"]:
        transport = "multipart"
    elif media == ["application/json", "multipart/form-data"]:
        transport = "content_type_select"
    else:
        raise ValueError(f"unsupported request media combination: {media}")
    return media, schemas, transport


def response_details(operation: dict[str, Any], components: dict[str, Any]) -> tuple[list[str], dict[str, dict[str, Any]]]:
    media: set[str] = set()
    responses: dict[str, dict[str, Any]] = {}
    for status, response in operation.get("responses", {}).items():
        if not isinstance(response, dict):
            raise ValueError(f"invalid response declaration for {status}")
        response = resolve_component_reference(response, components, "responses")
        content = response.get("content", {})
        if not isinstance(content, dict):
            raise ValueError("response content must be an object")
        status_schemas: dict[str, Any] = {}
        for media_type, media_type_data in content.items():
            if not isinstance(media_type_data, dict) or not isinstance(media_type_data.get("schema"), dict):
                raise ValueError(f"invalid response media declaration: {media_type}")
            schema = media_type_data["schema"]
            validate_schema(schema, components)
            media.add(media_type)
            status_schemas[media_type] = schema
        responses[str(status)] = dict(sorted(status_schemas.items()))
    return sorted(media), dict(sorted(responses.items()))


def target_selectors(path: str) -> list[str]:
    names = set(PATH_PARAMETER.findall(path))
    selectors = []
    if "org_id" in names:
        selectors.append("org")
    if "site_id" in names:
        selectors.append("site")
    if "msp_id" in names:
        selectors.append("msp")
    return selectors or ["none"]


def pagination(parameters: list[dict[str, Any]]) -> str:
    names = {parameter["name"] for parameter in parameters if parameter["in"] == "query"}
    if "search_after" in names:
        return "search_after"
    if "page" in names or "limit" in names:
        return "page_limit"
    return "none"


def operation_record(path: str, method: str, operation: dict[str, Any], path_parameters: list[Any], components: dict[str, Any], classification: dict[str, str], verification: dict[str, str]) -> dict[str, Any]:
    if not path.startswith("/api/v1/") or any(part in {"", ".", ".."} for part in path.split("/")[1:]) or "?" in path or "#" in path:
        raise ValueError(f"unsafe path template: {path!r}")
    operation_id = operation.get("operationId")
    if not isinstance(operation_id, str) or not operation_id:
        raise ValueError(f"missing operationId for {method} {path}")
    parameters_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for raw in [*path_parameters, *operation.get("parameters", [])]:
        parameter = resolve_parameter(raw, components)
        name, location = parameter.get("name"), parameter.get("in")
        if not isinstance(name, str) or location not in {"path", "query", "header", "cookie"}:
            raise ValueError(f"invalid parameter on {method} {path}")
        schema = parameter.get("schema")
        if not isinstance(schema, dict):
            raise ValueError(f"missing parameter schema on {method} {path}: {location} {name}")
        validate_schema(schema, components)
        parameters_by_key[(location, name)] = {
            "name": name,
            "in": location,
            "required": bool(parameter.get("required", False)),
            "schema": schema,
        }
    parameters = sorted(parameters_by_key.values(), key=lambda value: (value["in"], value["name"]))
    declared_path_parameters = {parameter["name"] for parameter in parameters if parameter["in"] == "path"}
    if set(PATH_PARAMETER.findall(path)) != declared_path_parameters:
        raise ValueError(f"path parameter mismatch on {method} {path}")
    request_media, request_schemas, transport = request_details(operation, components)
    response_media, responses = response_details(operation, components)
    action = classification["action"]
    if action not in {"ordinary_read", "privileged_read", "create", "update", "delete", "execute"}:
        raise ValueError(f"unsupported reviewed action for {method} {path}: {action!r}")
    verification_policy = verification.get("mode")
    if action in {"ordinary_read", "privileged_read"}:
        if verification:
            raise ValueError(f"read operation must not have verification policy: {method} {path}")
        verification_policy = "none"
    elif verification_policy == "follow_up_read":
        if set(verification) != {"mode", "operation_id", "predicate"}:
            raise ValueError(f"invalid follow-up verification policy for {method} {path}")
    elif verification_policy == "api_acknowledged":
        if set(verification) != {"mode", "reason"} or not verification["reason"]:
            raise ValueError(f"unreasoned API-acknowledged verification policy for {method} {path}")
    else:
        raise ValueError(f"missing verification policy for mutation {method} {path}")
    scope = path.split("/")[3]
    record = {
        "operation_key": f"{method} {path}",
        "operation_id": operation_id,
        "tool": tool_name(operation_id),
        "method": method,
        "path": path,
        "scope": scope,
        "summary": operation.get("summary", operation_id),
        "openapi_tags": sorted(operation.get("tags", [])),
        "capability": action,
        "action": action,
        "classification_reason": classification["reason"],
        "classification_source_fingerprint": classification["source_fingerprint"],
        "parameters": parameters,
        "target_selectors": target_selectors(path),
        "request_media_types": request_media,
        "request_schemas": request_schemas,
        "response_media_types": response_media,
        "responses": responses,
        "pagination": pagination(parameters),
        "verification": verification_policy,
        "follow_up_operation_id": verification.get("operation_id"),
        "verification_predicate": verification.get("predicate"),
        "verification_reason": verification.get("reason"),
        "transport": transport,
    }
    record["source_fingerprint"] = sha256(record)
    return record


def load_locked_json(path: Path, expected_sha256: str, label: str) -> dict[str, Any]:
    source = path.read_bytes()
    if hashlib.sha256(source).hexdigest() != expected_sha256:
        raise ValueError(f"{label} SHA-256 does not match its audited snapshot")
    value = json.loads(source)
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def operation_source_fingerprint(operation_key: str, method: str, path: str, operation: dict[str, Any]) -> str:
    return sha256({"operation_key": operation_key, "operation_id": operation["operationId"], "method": method, "path": path, "operation": operation})


def load_policy(path: Path, operation_metadata: dict[str, tuple[str, str]]) -> tuple[dict[str, dict[str, str]], dict[str, dict[str, str]]]:
    policy = json.loads(path.read_bytes())
    if not isinstance(policy, dict) or policy.get("policy_version") != 1 or policy.get("source_sha256") != EXPECTED_SHA256:
        raise ValueError("operation policy version/source lock is invalid")
    classification = policy.get("classification")
    verification = policy.get("verification")
    if not isinstance(classification, dict) or set(classification) != set(operation_metadata):
        raise ValueError("operation classification policy coverage is incomplete or has extra entries")
    rows: dict[str, dict[str, str]] = {}
    for key, row in classification.items():
        if not isinstance(row, dict) or set(row) != {"operation_id", "action", "reason", "source_fingerprint"}:
            raise ValueError(f"invalid classification policy row: {key}")
        operation_id, fingerprint = operation_metadata[key]
        if row["operation_id"] != operation_id or row["source_fingerprint"] != fingerprint or not isinstance(row["reason"], str) or not row["reason"]:
            raise ValueError(f"classification policy metadata mismatch: {key}")
        rows[key] = row
    semantic_keys = {key for key, row in rows.items() if row["action"] not in {"ordinary_read", "privileged_read"}}
    if not isinstance(verification, dict) or set(verification) != semantic_keys:
        raise ValueError("operation verification policy coverage is incomplete or has extra entries")
    allowed_reasons = {"no_follow_up_get", "collection_identity_unavailable", "schema_not_comparable", "asynchronous_operation", "operational_command", "external_side_effect", "mixed_effect", "delete_absence_not_specified"}
    for key, row in verification.items():
        if not isinstance(row, dict):
            raise ValueError(f"invalid verification policy row: {key}")
        if row.get("mode") == "follow_up_read" and set(row) == {"mode", "operation_id", "predicate"} and row["predicate"] == "request_projection_equals_response" and isinstance(row["operation_id"], str):
            continue
        if row.get("mode") == "api_acknowledged" and set(row) == {"mode", "reason"} and row["reason"] in allowed_reasons:
            continue
        raise ValueError(f"invalid verification policy row: {key}")
    return rows, verification


def frozen_parity(records: list[dict[str, Any]], inventory: dict[str, Any], source: dict[str, str]) -> dict[str, Any]:
    """Map only audited frozen wrapper records; current-spec gaps are exceptions."""
    wrappers = inventory.get("registered_surface", {}).get("tools")
    comparison = inventory.get("wrapper_vs_vendored", {})
    if not isinstance(wrappers, list) or len(wrappers) != 1050:
        raise ValueError("frozen inventory wrapper count is invalid")
    records_by_id = {record["operation_id"]: record for record in records}
    mapped: list[dict[str, Any]] = []
    stale: list[dict[str, Any]] = []
    for wrapper in wrappers:
        if not isinstance(wrapper, dict):
            raise ValueError("frozen inventory wrapper record is invalid")
        operation_id = wrapper.get("operation_id")
        if operation_id is None:
            stale.append(wrapper)
            continue
        record = records_by_id.get(operation_id)
        if record is None or any(wrapper.get(field) != record[field] for field in ("tool", "method", "path", "scope")):
            raise ValueError(f"frozen wrapper does not map exactly to current operation: {wrapper.get('tool')!r}")
        try:
            frozen_capability = {"READ": "read", "WRITE": "write", "WRITE_DELETE": "write_delete"}[wrapper["capability"]]
        except (KeyError, TypeError) as error:
            raise ValueError(f"unknown frozen wrapper capability for {wrapper.get('tool')!r}: {wrapper.get('capability')!r}") from error
        frozen_transport = "none" if not record["request_media_types"] else "json"
        mapped.append({
            "operation_key": record["operation_key"], "operation_id": record["operation_id"], "tool": record["tool"],
            "method": record["method"], "path": record["path"], "scope": record["scope"],
            "openapi_tags": record["openapi_tags"],
            "capability": frozen_capability,
            "request_media_types": record["request_media_types"], "transport": frozen_transport,
            "source_fingerprint": record["source_fingerprint"],
        })
    mapped.sort(key=lambda record: record["operation_key"])
    missing_tools = comparison.get("missing_tools")
    extra_tools = comparison.get("extra_tools")
    if not isinstance(missing_tools, list) or not isinstance(extra_tools, list) or len(mapped) != 1049 or len(missing_tools) != 10 or len(stale) != 1 or len(extra_tools) != 1:
        raise ValueError("frozen wrapper/current-spec accounting is invalid")
    exceptions: list[dict[str, str]] = []
    mapped_tools = {record["tool"] for record in mapped}
    for tool in sorted(missing_tools):
        matching = [record for record in records if record["tool"] == tool]
        if len(matching) != 1 or tool in mapped_tools:
            raise ValueError(f"frozen missing-tool identity is invalid: {tool!r}")
        exceptions.append({"operation_key": matching[0]["operation_key"], "status": "unsupported", "reason": f"Missing frozen reference wrapper {tool}; audited in docs/mist-api/frozen-reference-inventory.json.", "issue": "docs/mist-api/frozen-reference-inventory.json", "expires_on": "2026-08-28"})
    stale_wrapper = stale[0]
    if stale_wrapper.get("tool") != extra_tools[0]:
        raise ValueError("frozen stale wrapper identity is invalid")
    exceptions.append({"operation_key": f"{stale_wrapper['method']} {stale_wrapper['path']}", "status": "unsupported", "reason": f"Stale frozen wrapper {stale_wrapper['tool']} is excluded; no current OpenAPI operation exists. Audited in docs/mist-api/frozen-reference-inventory.json.", "issue": "docs/mist-api/frozen-reference-inventory.json", "expires_on": "2026-08-28"})
    for record in mapped:
        media = record["request_media_types"]
        if "multipart/form-data" in media:
            kind = "multipart-only" if media == ["multipart/form-data"] else "mixed-media"
            exceptions.append({"operation_key": record["operation_key"], "status": "transport_blocked", "reason": f"Frozen wrapper {record['tool']} is JSON-only; {kind} media is blocked. Audited in docs/mist-api/frozen-reference-inventory.json.", "issue": "docs/mist-api/frozen-reference-inventory.json", "expires_on": "2026-08-28"})
    blocked_count = sum(item["status"] == "transport_blocked" for item in exceptions)
    if len(exceptions) != 34 or blocked_count != 23:
        raise ValueError(f"frozen transport-gap accounting is invalid: exceptions={len(exceptions)}, blocked={blocked_count}")
    if any(not item["issue"] or date.fromisoformat(item["expires_on"]) <= date.today() for item in exceptions):
        raise ValueError("frozen parity exception is unaudited or expired")
    if len({(item["operation_key"], item["status"]) for item in exceptions}) != len(exceptions):
        raise ValueError("frozen parity exceptions contain duplicate identities")
    exceptions.sort(key=lambda item: (item["operation_key"], item["status"]))
    return {"manifest_version": 1, "platform": "mist", "source": source, "naming": {"tool_prefix": "mist_", "operation_id_transform": "unicode_casefold_snake_case_v1", "collision_policy": "fail"}, "capability_policy": {"GET": "read", "POST": "write", "PUT": "write", "PATCH": "write", "DELETE": "write_delete"}, "operations": mapped, "exceptions": exceptions}


def generate(spec: Path, policy_path: Path, inventory_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    source_bytes = spec.read_bytes()
    if hashlib.sha256(source_bytes).hexdigest() != EXPECTED_SHA256:
        raise ValueError("source SHA-256 does not match the audited Mist snapshot")
    document = json.loads(source_bytes)
    if document.get("openapi") != "3.1.0" or document.get("info", {}).get("version") != "2607.1.0":
        raise ValueError("source OpenAPI/API version does not match the audited Mist snapshot")
    components = document.get("components", {})
    if not isinstance(components, dict):
        raise ValueError("components must be an object")
    for schema_name, schema in components.get("schemas", {}).items():
        if not isinstance(schema, dict):
            raise ValueError(f"invalid components schema: {schema_name}")
        validate_schema(schema, components, (schema_name,))
    raw_operations: list[tuple[str, str, dict[str, Any], list[Any]]] = []
    operation_metadata: dict[str, tuple[str, str]] = {}
    for path, path_item in document.get("paths", {}).items():
        if not isinstance(path_item, dict):
            raise ValueError(f"path item is not an object: {path}")
        path_parameters = path_item.get("parameters", [])
        for raw_method, operation in path_item.items():
            if raw_method in PATH_ITEM_METADATA:
                continue
            if raw_method not in ALLOWED_METHODS:
                raise ValueError(f"unsupported HTTP method {raw_method!r} on {path}")
            if not isinstance(operation, dict):
                raise ValueError(f"operation is not an object: {raw_method} {path}")
            method = raw_method.upper()
            key = f"{method} {path}"
            raw_operations.append((path, method, operation, path_parameters))
            operation_metadata[key] = (operation.get("operationId", ""), operation_source_fingerprint(key, method, path, operation))
    classification, verification = load_policy(policy_path, operation_metadata)
    records = []
    for path, method, operation, path_parameters in raw_operations:
        key = f"{method} {path}"
        records.append(operation_record(path, method, operation, path_parameters, components, classification[key], verification.get(key, {})))
    records.sort(key=lambda record: record["operation_key"])
    for field in ("operation_id", "tool", "operation_key"):
        values = [record[field] for record in records]
        if len(values) != len(set(values)):
            raise ValueError(f"duplicate {field} in catalog")
    if len(records) != 1059:
        raise ValueError(f"incomplete operation accounting: expected 1059, found {len(records)}")
    records_by_id = {record["operation_id"]: record for record in records}
    for record in records:
        if record["verification"] == "follow_up_read":
            follow_up = records_by_id.get(record["follow_up_operation_id"])
            if follow_up is None or follow_up["method"] != "GET" or record["verification_predicate"] != "request_projection_equals_response":
                raise ValueError(f"invalid catalogued follow-up read for {record['operation_key']}")
    media_accounting = {
        "json_only_operations": sum(record["request_media_types"] == ["application/json"] for record in records),
        "multipart_only_operations": sum(record["request_media_types"] == ["multipart/form-data"] for record in records),
        "mixed_media_operations": sum(record["request_media_types"] == ["application/json", "multipart/form-data"] for record in records),
        "json_media_entries": sum("application/json" in record["request_media_types"] for record in records),
        "multipart_media_entries": sum("multipart/form-data" in record["request_media_types"] for record in records),
    }
    if media_accounting != {"json_only_operations": 333, "multipart_only_operations": 16, "mixed_media_operations": 7, "json_media_entries": 340, "multipart_media_entries": 23}:
        raise ValueError(f"request media accounting changed: {media_accounting}")
    source = {"url": SOURCE_URL, "revision": UPSTREAM_COMMIT, "sha256": EXPECTED_SHA256, "openapi_version": "3.1.0", "api_version": "2607.1.0"}
    catalog = {
        "catalog_version": 1,
        "platform": "mist",
        "source": source,
        "components": components,
        "operations": records,
        "audit": {
            "reference_commit": "2b91700b9049c2c27ce6a811a272f2ddfa8091e5",
            "operation_wrappers": 1050,
            "meta_tools": 3,
            "missing_current_operations": 10,
            "stale_unmatched_wrappers": 1,
            "stale_wrapper_tool": "mist_get_org_aos_register_cmd",
            "media_accounting": media_accounting,
        },
    }
    inventory = load_locked_json(inventory_path, EXPECTED_INVENTORY_SHA256, "frozen reference inventory")
    parity = frozen_parity(records, inventory, source)
    return catalog, parity


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, default=ROOT / "docs/mist-api/mist-openapi.json")
    parser.add_argument("--policy", type=Path, default=ROOT / "docs/mist-api/operation-policy.json")
    parser.add_argument("--inventory", type=Path, default=ROOT / "docs/mist-api/frozen-reference-inventory.json")
    parser.add_argument("--catalog", type=Path, default=ROOT / "docs/mist-api/catalog.json")
    parser.add_argument("--parity", type=Path, default=ROOT / "docs/mist-api/parity.json")
    arguments = parser.parse_args()
    try:
        catalog, parity = generate(arguments.spec, arguments.policy, arguments.inventory)
        write_json(arguments.catalog, catalog)
        write_json(arguments.parity, parity)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"generate-mist-catalog: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
