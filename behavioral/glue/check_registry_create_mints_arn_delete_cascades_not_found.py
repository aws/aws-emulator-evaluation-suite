"""registry-create-mints-arn-delete-cascades-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "registry-create-mints-arn-delete-cascades-not-found"
GROUP = "schema-registry"
SERVICES = ["glue"]

_SCHEMA_DEFINITION = json.dumps(
    {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {"orderId": {"type": "string"}},
        "required": ["orderId"],
    }
)


@tags("axis:rejection", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRegistry mints the registry's exact ARN and ListRegistries lists it once;
    once DeleteRegistry settles, GetRegistry, UpdateRegistry and GetSchema for a schema
    inside it all raise EntityNotFoundException and ListRegistries omits it."""
    glue = ctx.client("glue")

    registry_name = ctx.unique_name("sim2real-behav-glue-registry-")
    expected_arn = f"arn:aws:glue:{ctx.region}:{ctx.account}:registry/{registry_name}"

    created = glue.create_registry(RegistryName=registry_name, Description="sim2real behavioral registry")
    ctx.on_cleanup(_teardown(lambda: glue.delete_registry(RegistryId={"RegistryName": registry_name}),
                              "EntityNotFoundException"))
    assert created["RegistryArn"] == expected_arn, (
        f"expected CreateRegistry to mint ARN {expected_arn!r}, got {created['RegistryArn']!r}"
    )
    assert created["RegistryName"] == registry_name, (
        f"expected CreateRegistry to echo RegistryName={registry_name!r}, got {created['RegistryName']!r}"
    )

    got = glue.get_registry(RegistryId={"RegistryName": registry_name})
    assert got["Status"] == "AVAILABLE", f"expected a fresh registry's Status AVAILABLE, got {got['Status']!r}"
    assert got["RegistryArn"] == expected_arn, (
        f"expected GetRegistry's RegistryArn {expected_arn!r}, got {got['RegistryArn']!r}"
    )

    listed = _matching_registries(glue, registry_name)
    assert len(listed) == 1, f"expected ListRegistries to list {registry_name!r} exactly once, got {listed!r}"
    assert listed[0]["RegistryArn"] == expected_arn, (
        f"expected the listed entry's RegistryArn {expected_arn!r}, got {listed[0]['RegistryArn']!r}"
    )

    schema_name = ctx.unique_name("sim2real-behav-glue-schema-")
    schema_created = glue.create_schema(
        RegistryId={"RegistryName": registry_name},
        SchemaName=schema_name,
        DataFormat="JSON",
        Compatibility="NONE",
        SchemaDefinition=_SCHEMA_DEFINITION,
    )
    schema_arn = schema_created["SchemaArn"]
    got_schema = glue.get_schema(SchemaId={"SchemaArn": schema_arn})
    assert got_schema["SchemaStatus"] == "AVAILABLE", (
        f"expected a fresh schema's SchemaStatus AVAILABLE, got {got_schema['SchemaStatus']!r}"
    )

    deleted = glue.delete_registry(RegistryId={"RegistryName": registry_name})
    assert deleted["Status"] == "DELETING", f"expected DeleteRegistry's Status DELETING, got {deleted['Status']!r}"
    assert deleted["RegistryArn"] == expected_arn, (
        f"expected DeleteRegistry's RegistryArn {expected_arn!r}, got {deleted['RegistryArn']!r}"
    )
    assert deleted["RegistryName"] == registry_name, (
        f"expected DeleteRegistry's RegistryName {registry_name!r}, got {deleted['RegistryName']!r}"
    )

    _poll_until_error(lambda: glue.get_registry(RegistryId={"RegistryName": registry_name}))

    _REGISTRY_GONE = (
        "EntityNotFoundException",
        f"Registry is not found. RegistryName: {registry_name}, RegistryArn: null",
    )
    expect_error(lambda: glue.get_registry(RegistryId={"RegistryName": registry_name}), *_REGISTRY_GONE)

    _UPDATE_GONE = (
        "EntityNotFoundException",
        f"Registry is not found. RegistryName: {registry_name}, RegistryArn: null",
    )
    expect_error(
        lambda: glue.update_registry(RegistryId={"RegistryName": registry_name}, Description="updated"),
        *_UPDATE_GONE,
    )

    _SCHEMA_GONE = (
        "EntityNotFoundException",
        f"Registry is not found. RegistryName: {registry_name}",
    )
    expect_error(lambda: glue.get_schema(SchemaId={"SchemaArn": schema_arn}), *_SCHEMA_GONE)

    listed_after = _matching_registries(glue, registry_name)
    assert listed_after == [], f"expected ListRegistries to omit the deleted registry, still saw {listed_after!r}"


# ===== helpers =====
def _matching_registries(glue, registry_name: str) -> list:
    """Every ListRegistries entry named ``registry_name``, paginated."""
    matches = []
    for page in glue.get_paginator("list_registries").paginate():
        matches.extend(r for r in page["Registries"] if r["RegistryName"] == registry_name)
    return matches


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def expect_error(fn, code: str, message: str) -> None:
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected error code {code!r}, got {got_code!r} (message {got_message!r})"
    assert got_message == message, f"expected error message {message!r}, got {got_message!r}"


def _poll_until_error(fn, *, budget_s: float = 180.0, interval_s: float = 5.0) -> None:
    """Poll ``fn`` until it raises a ClientError; never asserts which one, just that it settles."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            result = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(
                f"expected the deleting registry to settle to an error within {budget_s}s, "
                f"last read still succeeded: {result!r}"
            )
        time.sleep(interval_s)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` codes mean
    the resource is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
