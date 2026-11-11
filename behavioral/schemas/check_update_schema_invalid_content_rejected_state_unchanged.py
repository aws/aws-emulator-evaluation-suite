"""update-schema-invalid-content-rejected-state-unchanged."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-schema-invalid-content-rejected-state-unchanged"
GROUP = "overly-permissive"
SERVICES = ["schemas"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSchema with syntactically-invalid Content is rejected and never mints a new version."""
    schemas = ctx.client("schemas")
    registry = ctx.unique_name("sim2real-schemas-reg-")
    schemas.create_registry(RegistryName=registry, Tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: schemas.delete_registry(RegistryName=registry))

    schema_name = ctx.unique_name("sim2real-schemas-sch-")
    original_content = _openapi3_content("Widget")
    schemas.create_schema(
        RegistryName=registry,
        SchemaName=schema_name,
        Type="OpenApi3",
        Content=original_content,
        Tags={"sim2real": "true"},
    )
    ctx.on_cleanup(lambda: schemas.delete_schema(RegistryName=registry, SchemaName=schema_name))

    err = _error(
        lambda: schemas.update_schema(
            RegistryName=registry, SchemaName=schema_name, Type="OpenApi3", Content="{not-valid-json"
        )
    )
    assert err["Code"] == "BadRequestException", f"unexpected error: {err!r}"
    assert err["Message"] == (
        "Content is not valid JSON: invalid character 'n' looking for beginning of object key "
        "string at offset 2"
    ), f"unexpected update_invalid message: {err['Message']!r}"

    unaffected = schemas.describe_schema(RegistryName=registry, SchemaName=schema_name)
    assert unaffected["SchemaVersion"] == "1"
    assert json.loads(unaffected["Content"]) == json.loads(original_content)

    # Positive control: a syntactically valid update in the same file still succeeds.
    valid_content = _openapi3_content("Widget", {"color": {"type": "string"}})
    valid_update = schemas.update_schema(
        RegistryName=registry, SchemaName=schema_name, Type="OpenApi3", Content=valid_content
    )
    assert valid_update["SchemaVersion"] == "2"

    # Independent read at the destination — not the mutating call's own response.
    confirmed = schemas.describe_schema(RegistryName=registry, SchemaName=schema_name)
    assert confirmed["SchemaVersion"] == "2"
    assert json.loads(confirmed["Content"]) == json.loads(valid_content)


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses must not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _openapi3_content(title: str, extra_props: dict | None = None) -> str:
    props = {"id": {"type": "string"}}
    if extra_props:
        props.update(extra_props)
    return json.dumps(
        {
            "openapi": "3.0.0",
            "info": {"version": "1.0.0", "title": title},
            "paths": {},
            "components": {"schemas": {"Event": {"type": "object", "properties": props}}},
        }
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
