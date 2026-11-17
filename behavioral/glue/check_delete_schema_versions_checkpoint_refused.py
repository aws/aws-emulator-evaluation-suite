"""delete-schema-versions-checkpoint-refused."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-schema-versions-checkpoint-refused"
GROUP = "schema-registry"
SERVICES = ["glue"]

_CHECKPOINT_REFUSED = ("InvalidInputException", "Cannot delete checkpoint version.")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def expect_error(fn, code: str, message: str) -> None:
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected code {code!r}, got {got_code!r} (message {got_message!r})"
    assert got_message == message, f"expected message {message!r}, got {got_message!r}"


def _definition(*extra_fields: str) -> str:
    props = {"id": {"type": "string"}}
    for field in extra_fields:
        props[field] = {"type": "string"}
    return json.dumps({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": props,
        "required": ["id"],
    })


def _poll_until_gone(glue, schema_arn: str, version: int, *, budget_s: float = 60.0,
                      interval_s: float = 3.0) -> str:
    """Poll GetSchemaVersion to its terminal not-found state; returns the exact message."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            glue.get_schema_version(
                SchemaId={"SchemaArn": schema_arn},
                SchemaVersionNumber={"VersionNumber": version},
            )
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == "EntityNotFoundException":
                return err.get("Message")
            raise
        if time.monotonic() > deadline:
            raise AssertionError(f"version {version} of {schema_arn} still readable after {budget_s}s")
        time.sleep(interval_s)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """On a NONE-compatibility schema, DeleteSchemaVersions refuses the checkpoint version
    outright while a non-checkpoint version in the same schema deletes, and GetSchema and
    GetSchemaVersion reflect only the version that is actually gone.
    """
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real-behav-glue-schema-")

    created = glue.create_schema(
        SchemaName=name, DataFormat="JSON", Compatibility="NONE", SchemaDefinition=_definition()
    )
    schema_arn = created["SchemaArn"]
    ctx.on_cleanup(lambda: glue.delete_schema(SchemaId={"SchemaArn": schema_arn}))
    assert created["SchemaCheckpoint"] == 1, f"first checkpoint was {created['SchemaCheckpoint']!r}"

    v2 = glue.register_schema_version(
        SchemaId={"SchemaArn": schema_arn}, SchemaDefinition=_definition("extra")
    )
    assert v2["VersionNumber"] == 2, f"expected version 2, got {v2['VersionNumber']!r}"

    v3_definition = _definition("extra", "more")
    v3 = glue.register_schema_version(SchemaId={"SchemaArn": schema_arn}, SchemaDefinition=v3_definition)
    assert v3["VersionNumber"] == 3, f"expected version 3, got {v3['VersionNumber']!r}"

    # Move the checkpoint off version 1, so the refusal below is about the checkpoint rule and
    # not about version 1 also being the schema's first version, which DeleteSchemaVersions
    # refuses for a different reason.
    glue.update_schema(SchemaId={"SchemaArn": schema_arn}, SchemaVersionNumber={"VersionNumber": 3})
    moved = glue.get_schema(SchemaId={"SchemaArn": schema_arn})
    assert moved["SchemaCheckpoint"] == 3, f"checkpoint did not move to 3: {moved['SchemaCheckpoint']!r}"

    expect_error(
        lambda: glue.delete_schema_versions(SchemaId={"SchemaArn": schema_arn}, Versions="3"),
        *_CHECKPOINT_REFUSED,
    )

    # Positive control, the legal neighbour: a version that is not the checkpoint deletes clean.
    deleted = glue.delete_schema_versions(SchemaId={"SchemaArn": schema_arn}, Versions="2")
    assert deleted["SchemaVersionErrors"] == [], (
        f"deleting the non-checkpoint version reported errors: {deleted['SchemaVersionErrors']!r}"
    )

    expected_gone = (
        "Schema version is not found. RegistryName: null, SchemaName: null, "
        f"SchemaArn: {schema_arn}, VersionNumber: 2, isLatestVersion: false"
    )
    gone_message = _poll_until_gone(glue, schema_arn, 2)
    assert gone_message == expected_gone, f"expected {expected_gone!r}, got {gone_message!r}"

    survivor = glue.get_schema_version(
        SchemaId={"SchemaArn": schema_arn}, SchemaVersionNumber={"VersionNumber": 3}
    )
    assert survivor["VersionNumber"] == 3, f"checkpoint version read back as {survivor['VersionNumber']!r}"
    assert survivor["Status"] == "AVAILABLE", f"checkpoint version status is {survivor['Status']!r}"
    assert survivor["SchemaDefinition"] == v3_definition, (
        "the checkpoint version's definition changed after the refused delete"
    )

    unchanged = glue.get_schema(SchemaId={"SchemaArn": schema_arn})
    assert unchanged["SchemaCheckpoint"] == 3, f"checkpoint moved to {unchanged['SchemaCheckpoint']!r}"
    assert unchanged["LatestSchemaVersion"] == 3, (
        f"latest version changed to {unchanged['LatestSchemaVersion']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
