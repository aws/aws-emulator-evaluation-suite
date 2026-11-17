"""schema-disabled-switch-blocks-compatible-version."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schema-disabled-switch-blocks-compatible-version"
GROUP = 'schema-compatibility'
SERVICES = ['glue']

ORDER_V1 = (
    '{"type":"record","name":"Order","namespace":"com.example","fields":['
    '{"name":"orderId","type":"long"}]}'
)
ORDER_V2 = (
    '{"type":"record","name":"Order","namespace":"com.example","fields":['
    '{"name":"orderId","type":"long"},'
    '{"name":"amount","type":["null","double"],"default":null}]}'
)
ORDER_V3 = (
    '{"type":"record","name":"Order","namespace":"com.example","fields":['
    '{"name":"orderId","type":"long"},'
    '{"name":"amount","type":["null","double"],"default":null},'
    '{"name":"currency","type":["null","string"],"default":null}]}'
)

_DISABLED_NO_VERSIONING = (
    "InvalidInputException",
    "Compatibility DISABLED does not allow versioning. SchemaId: "
    "SchemaId(schemaArn=null, schemaName={schema}, registryName={registry})",
)


def _refusal(fn):
    """Call ``fn()`` and return the (code, message) of the ClientError it raises."""
    try:
        outcome = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it returned {outcome!r}")


def expect_error(fn, code, message):
    got_code, got_message = _refusal(fn)
    assert got_code == code, f"expected error code {code!r}, got {got_code!r}"
    assert got_message == message, f"expected message {message!r}, got {got_message!r}"


def _until_terminal(glue, schema_id, version_number):
    """Return GetSchemaVersion's Status once it leaves PENDING, within a 30s budget."""
    budget = time.monotonic() + 30.0
    status = "PENDING"
    while status == "PENDING":
        if time.monotonic() > budget:
            raise AssertionError(f"version {version_number} still PENDING after 30s")
        status = glue.get_schema_version(
            SchemaId=schema_id, SchemaVersionNumber={"VersionNumber": version_number}
        )["Status"]
        if status == "PENDING":
            time.sleep(1.0)
    return status


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Switching a BACKWARD schema's Compatibility to DISABLED blocks a further version even
    when that version is itself BACKWARD-compatible, leaving ListSchemaVersions unchanged;
    switching to NONE then admits the identical definition as the next version.
    """
    glue = ctx.client("glue")
    registry = ctx.unique_name("sim2real-behav-registry-")
    glue.create_registry(RegistryName=registry, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_registry(RegistryId={"RegistryName": registry}))

    schema = ctx.unique_name("sim2real-behav-schema-")
    schema_id = {"RegistryName": registry, "SchemaName": schema}
    glue.create_schema(
        RegistryId={"RegistryName": registry},
        SchemaName=schema,
        DataFormat="AVRO",
        Compatibility="BACKWARD",
        SchemaDefinition=ORDER_V1,
        Tags={"sim2real": CHECK},
    )

    v2 = glue.register_schema_version(SchemaId=schema_id, SchemaDefinition=ORDER_V2)["VersionNumber"]
    v2_status = _until_terminal(glue, schema_id, v2)
    assert v2_status == "AVAILABLE", (
        f"positive control: the BACKWARD-compatible v2 did not reach AVAILABLE, got {v2_status}"
    )

    before = sorted(v["VersionNumber"] for v in glue.list_schema_versions(SchemaId=schema_id)["Schemas"])
    assert before == [1, v2], f"expected versions [1, {v2}] before the switch, got {before}"

    # Switching Compatibility requires a checkpoint; pin it at the version just proved AVAILABLE.
    glue.update_schema(
        SchemaId=schema_id, Compatibility="DISABLED", SchemaVersionNumber={"VersionNumber": v2}
    )

    disabled_code, disabled_message = _DISABLED_NO_VERSIONING
    expect_error(
        lambda: glue.register_schema_version(SchemaId=schema_id, SchemaDefinition=ORDER_V3),
        disabled_code,
        disabled_message.format(schema=schema, registry=registry),
    )

    after_disabled = sorted(
        v["VersionNumber"] for v in glue.list_schema_versions(SchemaId=schema_id)["Schemas"]
    )
    assert after_disabled == before, (
        f"a version blocked by DISABLED must not appear in ListSchemaVersions: "
        f"before={before} after={after_disabled}"
    )

    # Lift the block: NONE performs no compatibility check, so the identical, already
    # BACKWARD-compatible definition is admitted as the next version.
    glue.update_schema(
        SchemaId=schema_id, Compatibility="NONE", SchemaVersionNumber={"VersionNumber": v2}
    )
    v3 = glue.register_schema_version(SchemaId=schema_id, SchemaDefinition=ORDER_V3)["VersionNumber"]
    assert v3 == 3, f"expected the admitted version to be numbered 3, got {v3}"
    v3_status = _until_terminal(glue, schema_id, v3)
    assert v3_status == "AVAILABLE", (
        f"expected the previously blocked definition to reach AVAILABLE under NONE, got {v3_status}"
    )

    after_none = sorted(
        v["VersionNumber"] for v in glue.list_schema_versions(SchemaId=schema_id)["Schemas"]
    )
    assert after_none == [1, v2, 3], f"expected versions [1, {v2}, 3], got {after_none}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
