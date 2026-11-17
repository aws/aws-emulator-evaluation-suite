"""list-schema-versions-max-results-zero-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-schema-versions-max-results-zero-rejected"
GROUP = "negative-classes"
SERVICES = ["glue"]

_V1 = (
    '{"type":"record","name":"Order","namespace":"com.example",'
    '"fields":[{"name":"id","type":"long"}]}'
)

_MAX_RESULTS_OUT_OF_RANGE = (
    "InvalidInputException",
    "MaxResults cannot be greater than 100 (or) less than or equal to 0. MaxResults: 0",
)


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListSchemaVersions refuses MaxResults=0 with InvalidInputException and its exact
    message, while MaxResults=1 on the same schema still lists the one version that exists.
    """
    glue = ctx.client("glue")
    # botocore enforces the MaxResultsNumber range client-side before any request is sent;
    # disabling that check lets the AWS-decided refusal through instead of a ParamValidationError.
    glue_unvalidated = ctx.client("glue", config=Config(parameter_validation=False))
    registry = ctx.unique_name("sim2real-behav-registry-")
    glue.create_registry(RegistryName=registry)
    ctx.on_cleanup(lambda: glue.delete_registry(RegistryId={"RegistryName": registry}))

    schema_name = ctx.unique_name("sim2real-behav-orders-")
    sid = {"RegistryName": registry, "SchemaName": schema_name}
    created = glue.create_schema(
        RegistryId={"RegistryName": registry},
        SchemaName=schema_name,
        DataFormat="AVRO",
        Compatibility="BACKWARD",
        SchemaDefinition=_V1,
    )
    ctx.on_cleanup(lambda: glue.delete_schema(SchemaId=sid))

    expect_error(
        lambda: glue_unvalidated.list_schema_versions(SchemaId=sid, MaxResults=0),
        *_MAX_RESULTS_OUT_OF_RANGE,
    )

    # positive control: the same schema, same call shape, with a valid MaxResults still lists it
    page = glue.list_schema_versions(SchemaId=sid, MaxResults=1)
    assert len(page["Schemas"]) == 1, f"expected exactly 1 entry, got {page['Schemas']}"
    assert page["Schemas"][0]["SchemaVersionId"] == created["SchemaVersionId"], (
        f"expected the one existing version {created['SchemaVersionId']!r}, got {page['Schemas'][0]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
