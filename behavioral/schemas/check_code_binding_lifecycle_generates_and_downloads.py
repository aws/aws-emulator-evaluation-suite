"""code-binding-lifecycle-generates-and-downloads."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "code-binding-lifecycle-generates-and-downloads"
GROUP = "state"
SERVICES = ["schemas"]

_MODEL_NAME = "Event"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutCodeBinding kicks off async generation that reaches CREATE_COMPLETE and yields a downloadable zip
    whose contents are generated from this schema, not a canned response."""
    schemas = ctx.client("schemas")
    registry = ctx.unique_name("sim2real-schemas-reg-")
    schemas.create_registry(RegistryName=registry, Tags={"Environment": "test", "Team": "sim2real"})
    ctx.on_cleanup(lambda: schemas.delete_registry(RegistryName=registry))

    schema_name = ctx.unique_name("sim2real-schemas-sch-")
    schemas.create_schema(
        RegistryName=registry,
        SchemaName=schema_name,
        Type="OpenApi3",
        Content=_openapi3_content("Widget"),
        Tags={"Environment": "test", "Team": "sim2real"},
    )
    ctx.on_cleanup(lambda: schemas.delete_schema(RegistryName=registry, SchemaName=schema_name))

    pre = _error(
        lambda: schemas.describe_code_binding(Language="Java8", RegistryName=registry, SchemaName=schema_name)
    )
    assert pre["Code"] == "NotFoundException", f"expected NotFoundException before PutCodeBinding, got {pre!r}"
    assert pre["Message"] == (
        f"Code bindings for schema with name {schema_name} and version 1 language Java8 not found."
    ), f"unexpected describe_code_binding_pre message: {pre['Message']!r}"

    schemas.put_code_binding(Language="Java8", RegistryName=registry, SchemaName=schema_name)

    final = _poll_until(
        lambda: schemas.describe_code_binding(Language="Java8", RegistryName=registry, SchemaName=schema_name),
        lambda resp: resp["Status"] != "CREATE_IN_PROGRESS",
        timeout_s=90.0,
    )
    assert final["Status"] == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {final['Status']!r}"

    source = schemas.get_code_binding_source(
        Language="Java8", RegistryName=registry, SchemaName=schema_name
    )
    body = source["Body"].read()
    assert body[:2] == b"PK", f"expected a zip local-file-header signature, got {body[:2]!r}"

    archive = zipfile.ZipFile(io.BytesIO(body))
    assert archive.testzip() is None, "zip archive has a corrupt member"
    names = archive.namelist()
    assert names, "zip archive has no entries"
    sanitized_schema_name = schema_name.replace("-", "_")
    assert any(sanitized_schema_name in name for name in names), (
        f"expected a package path derived from schema name {schema_name!r} "
        f"(sanitized {sanitized_schema_name!r}), got {names!r}"
    )
    assert any(name.endswith(f"/{_MODEL_NAME}.java") for name in names), (
        f"expected a generated {_MODEL_NAME}.java model class matching the schema's "
        f"top-level component, got {names!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses must not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _openapi3_content(title: str, extra_props: dict | None = None) -> str:
    props = {"id": {"type": "string"}}
    if extra_props:
        props.update(extra_props)
    return json.dumps(
        {
            "openapi": "3.0.0",
            "info": {"version": "1.0.0", "title": title},
            "paths": {},
            "components": {"schemas": {_MODEL_NAME: {"type": "object", "properties": props}}},
        }
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
