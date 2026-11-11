"""register-version-on-disabled-compatibility-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-version-on-disabled-compatibility-fails"
GROUP = 'overly-permissive'
SERVICES = ['glue']

BASE_DEFINITION = (
    '{"type":"record","name":"User","fields":[{"name":"id","type":"string"}]}'
)
EVOLVED_DEFINITION = (
    '{"type":"record","name":"User","fields":[{"name":"id","type":"string"},'
    '{"name":"email","type":["null","string"],"default":null}]}'
)


def _wait_for_terminal_status(glue, schema_arn, version_number):
    status = None
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        status = glue.get_schema_version(
            SchemaId={"SchemaArn": schema_arn},
            SchemaVersionNumber={"VersionNumber": version_number},
        ).get("Status")
        if status in ("AVAILABLE", "FAILURE", "DELETING"):
            break
        time.sleep(1)
    return status


def _error(fn):
    """Call fn() and return (code, message) of the refusal; an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterSchemaVersion on a Compatibility=DISABLED schema raises InvalidInputException and
    adds no version, while the identical evolved definition on a BACKWARD twin becomes AVAILABLE."""
    glue = ctx.client("glue")
    schema_name = ctx.unique_name("sim2real-behav-schema-")
    created = glue.create_schema(
        SchemaName=schema_name,
        DataFormat="AVRO",
        Compatibility="DISABLED",
        SchemaDefinition=BASE_DEFINITION,
        Tags={"sim2real": CHECK},
    )
    schema_arn = created["SchemaArn"]
    ctx.on_cleanup(lambda: glue.delete_schema(SchemaId={"SchemaArn": schema_arn}))

    control_name = ctx.unique_name("sim2real-behav-schema-control-")
    control_created = glue.create_schema(
        SchemaName=control_name,
        DataFormat="AVRO",
        Compatibility="BACKWARD",
        SchemaDefinition=BASE_DEFINITION,
        Tags={"sim2real": CHECK},
    )
    control_arn = control_created["SchemaArn"]
    ctx.on_cleanup(lambda: glue.delete_schema(SchemaId={"SchemaArn": control_arn}))

    # DISABLED switches versioning off entirely: evolution must be rejected.
    code, message = _error(
        lambda: glue.register_schema_version(
            SchemaId={"SchemaArn": schema_arn},
            SchemaDefinition=EVOLVED_DEFINITION,
        )
    )
    assert code == "InvalidInputException", (
        f"expected InvalidInputException registering a version under DISABLED, got {code}"
    )
    assert message == f"Compatibility DISABLED does not allow versioning. SchemaId: SchemaId(schemaArn={schema_arn}, schemaName=null, registryName=null)", message

    # ...and the rejected registration must not have created a second version.
    versions = glue.list_schema_versions(SchemaId={"SchemaArn": schema_arn})["Schemas"]
    assert len(versions) == 1, (
        f"a rejected RegisterSchemaVersion must not add a version, got {len(versions)}"
    )

    # Positive control: the same definition on a schema differing only in Compatibility succeeds.
    control_registered = glue.register_schema_version(
        SchemaId={"SchemaArn": control_arn},
        SchemaDefinition=EVOLVED_DEFINITION,
    )
    control_status = _wait_for_terminal_status(
        glue, control_arn, control_registered["VersionNumber"]
    )
    assert control_status == "AVAILABLE", (
        f"the identical evolved version was refused on the BACKWARD control schema "
        f"too (status={control_status!r}) — the DISABLED rejection above cannot be "
        f"attributed to DISABLED compatibility"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
