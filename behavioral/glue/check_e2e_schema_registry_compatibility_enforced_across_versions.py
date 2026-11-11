"""e2e-schema-registry-compatibility-enforced-across-versions."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-schema-registry-compatibility-enforced-across-versions"
GROUP = "e2e"
SERVICES = ["glue"]

_V1 = json.dumps(
    {"type": "record", "name": "UserRecord", "namespace": "com.example", "fields": [{"name": "id", "type": "string"}]}
)
_V2_COMPATIBLE = json.dumps(
    {
        "type": "record",
        "name": "UserRecord",
        "namespace": "com.example",
        "fields": [
            {"name": "id", "type": "string"},
            {"name": "email", "type": "string", "default": ""},
        ],
    }
)
_V3_INCOMPATIBLE = json.dumps(
    {
        "type": "record",
        "name": "UserRecord",
        "namespace": "com.example",
        "fields": [
            {"name": "id", "type": "string"},
            {"name": "email", "type": "string", "default": ""},
            {"name": "age", "type": "int"},
        ],
    }
)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BACKWARD compatibility marks an incompatible version FAILURE; a compatible one is AVAILABLE.

    Glue reports the outcome in the version's Status, not as a client error.
    """
    glue = ctx.client("glue")

    registry_name = ctx.unique_name("sim2real-behav-reg-")
    registry_arn = glue.create_registry(RegistryName=registry_name, Tags={"sim2real": CHECK})["RegistryArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: glue.delete_registry(RegistryId={"RegistryArn": registry_arn})))

    schema_name = ctx.unique_name("sim2real-behav-schema-")
    create_resp = glue.create_schema(
        RegistryId={"RegistryName": registry_name},
        SchemaName=schema_name,
        DataFormat="AVRO",
        Compatibility="BACKWARD",
        SchemaDefinition=_V1,
        Tags={"sim2real": CHECK},
    )
    schema_arn = create_resp["SchemaArn"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: _delete_schema_and_wait(glue, schema_arn))
    )

    _wait_for_schema_status(glue, schema_arn, "AVAILABLE", timeout_s=60)

    # Positive control: a version that only adds a defaulted field is BACKWARD compatible.
    compat_resp = glue.register_schema_version(SchemaId={"SchemaArn": schema_arn}, SchemaDefinition=_V2_COMPATIBLE)
    compat_version_id = compat_resp["SchemaVersionId"]
    compat_status = _wait_for_version_status(glue, compat_version_id, timeout_s=90)
    assert compat_status == "AVAILABLE", f"expected compatible version AVAILABLE, got {compat_status}"

    # Break exactly one thing: add a required field with no default -> breaks BACKWARD compatibility.
    incompat_resp = glue.register_schema_version(SchemaId={"SchemaArn": schema_arn}, SchemaDefinition=_V3_INCOMPATIBLE)
    incompat_version_id = incompat_resp["SchemaVersionId"]
    incompat_status = _wait_for_version_status(glue, incompat_version_id, timeout_s=90)
    assert incompat_status == "FAILURE", f"expected incompatible version FAILURE, got {incompat_status}"

    # LatestSchemaVersion advances even to a FAILURE version; only the version's Status shows it.
    incompat_version_number = incompat_resp["VersionNumber"]
    schema_after_failure = glue.get_schema(SchemaId={"SchemaArn": schema_arn})
    assert schema_after_failure["LatestSchemaVersion"] == incompat_version_number, (
        f"expected LatestSchemaVersion to advance to the just-registered version "
        f"{incompat_version_number} even though it is FAILURE, got "
        f"{schema_after_failure['LatestSchemaVersion']!r}"
    )

    # A failed version is still stored and resolvable by its exact definition, with Status FAILURE.
    incompat_by_def = glue.get_schema_by_definition(
        SchemaId={"SchemaArn": schema_arn}, SchemaDefinition=_V3_INCOMPATIBLE
    )
    assert incompat_by_def["SchemaVersionId"] == incompat_version_id, (
        f"expected GetSchemaByDefinition to resolve the incompatible bytes back to "
        f"version id {incompat_version_id!r}, got {incompat_by_def['SchemaVersionId']!r}"
    )
    assert incompat_by_def["Status"] == "FAILURE", (
        f"expected the incompatible version to resolve with Status=FAILURE, got {incompat_by_def['Status']!r}"
    )

    # Positive control resolves correctly by definition and is AVAILABLE.
    by_def = glue.get_schema_by_definition(SchemaId={"SchemaArn": schema_arn}, SchemaDefinition=_V2_COMPATIBLE)
    assert by_def["SchemaVersionId"] == compat_version_id, (
        f"expected GetSchemaByDefinition to resolve the compatible bytes back to "
        f"version id {compat_version_id!r}, got {by_def['SchemaVersionId']!r}"
    )
    assert by_def["Status"] == "AVAILABLE", f"expected the compatible version to resolve AVAILABLE, got {by_def['Status']!r}"


def _ignore_not_found(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _wait_for_schema_status(glue, schema_arn: str, target: str, timeout_s: float, interval_s: float = 3.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = glue.get_schema(SchemaId={"SchemaArn": schema_arn})["SchemaStatus"]
        if status == target:
            return
        time.sleep(interval_s)
    raise AssertionError(f"schema never reached status {target} (last={status})")


def _wait_for_version_status(glue, version_id: str, timeout_s: float, interval_s: float = 3.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = glue.get_schema_version(SchemaVersionId=version_id)["Status"]
        if status in ("AVAILABLE", "FAILURE"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"schema version {version_id} never reached a terminal status (last={status})")


def _delete_schema_and_wait(glue, schema_arn: str, timeout_s: float = 60.0, interval_s: float = 3.0) -> None:
    glue.delete_schema(SchemaId={"SchemaArn": schema_arn})
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            glue.get_schema(SchemaId={"SchemaArn": schema_arn})
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFoundException":
                raise
            return
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
