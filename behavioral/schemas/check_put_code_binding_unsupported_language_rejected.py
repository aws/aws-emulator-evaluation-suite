"""put-code-binding-unsupported-language-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-code-binding-unsupported-language-rejected"
GROUP = "overly-permissive"
SERVICES = ["schemas"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutCodeBinding for an unsupported Language value is rejected; a supported language in the same file works."""
    schemas = ctx.client("schemas")
    registry = ctx.unique_name("sim2real-schemas-reg-")
    schemas.create_registry(RegistryName=registry, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: schemas.delete_registry(RegistryName=registry))

    schema_name = ctx.unique_name("sim2real-schemas-sch-")
    schemas.create_schema(
        RegistryName=registry,
        SchemaName=schema_name,
        Type="OpenApi3",
        Content=_openapi3_content("Widget"),
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: schemas.delete_schema(RegistryName=registry, SchemaName=schema_name))

    err = _error(
        lambda: schemas.put_code_binding(
            Language="Cobol99", RegistryName=registry, SchemaName=schema_name
        )
    )
    assert err["Code"] == "BadRequestException", f"unexpected error: {err!r}"
    assert err["Message"] == "Parameter CodeBindingLanguage doesn't match pattern ^(Java8|TypeScript3|Python36|Go1)$", f"unexpected put_code_binding_cobol message: {err['Message']!r}"

    # The rejected language never produced a binding; describing it is consistently rejected too.
    describe_err = _error(
        lambda: schemas.describe_code_binding(
            Language="Cobol99", RegistryName=registry, SchemaName=schema_name
        )
    )
    assert describe_err["Code"] == "BadRequestException", f"unexpected error: {describe_err!r}"
    assert describe_err["Message"] == "Parameter CodeBindingLanguage doesn't match pattern ^(Java8|TypeScript3|Python36|Go1)$", f"unexpected describe_code_binding_cobol message: {describe_err['Message']!r}"

    # Positive control: a supported language is accepted and starts async generation.
    control = schemas.put_code_binding(Language="Java8", RegistryName=registry, SchemaName=schema_name)
    assert control["Status"] == "CREATE_IN_PROGRESS"

    # Terminal read is independent of the mutating call: the binding is visible, and in the
    # expected in-flight/complete state, through a separate operation.
    describe = schemas.describe_code_binding(Language="Java8", RegistryName=registry, SchemaName=schema_name)
    assert describe["Status"] in ("CREATE_IN_PROGRESS", "CREATE_COMPLETE"), describe["Status"]


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses must not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _openapi3_content(title: str) -> str:
    return json.dumps(
        {
            "openapi": "3.0.0",
            "info": {"version": "1.0.0", "title": title},
            "paths": {},
            "components": {"schemas": {"Event": {"type": "object", "properties": {"id": {"type": "string"}}}}},
        }
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
