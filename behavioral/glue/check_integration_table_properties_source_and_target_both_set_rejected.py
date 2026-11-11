"""integration-table-properties-source-and-target-both-set-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "integration-table-properties-source-and-target-both-set-rejected"
GROUP = "representation"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateIntegrationTableProperties with both SourceTableConfig and TargetTableConfig fails with
    ValidationException, and the database's existing target-table properties survive the attempt.
    """
    glue = ctx.client("glue")
    real_database_arn, database_name, real_table_name = _create_glue_table(ctx)

    # ResourceArn must be the containing database's ARN: under a table ARN, Create succeeds but
    # Get 404s. Create validates neither TableName nor the ARN's resource type, so setting both
    # configs is the reliable rejection boundary.
    real_target_config = {"TargetTableName": real_table_name, "UnnestSpec": "TOPLEVEL"}
    glue.create_integration_table_properties(
        ResourceArn=real_database_arn,
        TableName=real_table_name,
        TargetTableConfig=real_target_config,
    )
    ctx.on_cleanup(
        lambda: glue.delete_integration_table_properties(
            ResourceArn=real_database_arn, TableName=real_table_name
        )
    )
    fetched_before = glue.get_integration_table_properties(
        ResourceArn=real_database_arn, TableName=real_table_name
    )
    assert fetched_before["TargetTableConfig"]["TargetTableName"] == real_table_name, (
        f"expected TargetTableName {real_table_name!r}, "
        f"got {fetched_before['TargetTableConfig'].get('TargetTableName')!r}"
    )
    assert fetched_before["TargetTableConfig"]["UnnestSpec"] == "TOPLEVEL", (
        f"expected UnnestSpec 'TOPLEVEL', got {fetched_before['TargetTableConfig'].get('UnnestSpec')!r}"
    )

    # Setting both Source and Target config on the same call must be rejected outright.
    expected_message = "Source and Target config can't both be set."
    code, message = _error_code(
        lambda: glue.create_integration_table_properties(
            ResourceArn=real_database_arn,
            TableName=real_table_name,
            SourceTableConfig={"Fields": ["id"]},
            TargetTableConfig={"TargetTableName": real_table_name, "UnnestSpec": "TOPLEVEL"},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: the real database's target-table properties are untouched by
    # the failed attempt.
    fetched_real = glue.get_integration_table_properties(
        ResourceArn=real_database_arn, TableName=real_table_name
    )
    assert fetched_real["TargetTableConfig"]["TargetTableName"] == real_table_name, (
        f"expected TargetTableName {real_table_name!r} to survive the rejected call, "
        f"got {fetched_real['TargetTableConfig'].get('TargetTableName')!r}"
    )
    assert fetched_real["TargetTableConfig"]["UnnestSpec"] == "TOPLEVEL", (
        f"expected UnnestSpec 'TOPLEVEL' to survive the rejected call, "
        f"got {fetched_real['TargetTableConfig'].get('UnnestSpec')!r}"
    )


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_glue_table(ctx) -> tuple[str, str, str]:
    """Create a throwaway Glue database + table and return (database_arn, db_name, table_name)."""
    glue = ctx.client("glue")
    database_name = ctx.unique_name("sim2real_itp2_db_").replace("-", "_").lower()
    glue.create_database(DatabaseInput={"Name": database_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=database_name))

    table_name = ctx.unique_name("sim2real_itp2_tbl_").replace("-", "_").lower()
    glue.create_table(
        DatabaseName=database_name,
        TableInput={
            "Name": table_name,
            "StorageDescriptor": {
                "Columns": [{"Name": "id", "Type": "string"}],
                "Location": f"s3://sim2real-behavioral-test-bucket/{database_name}/{table_name}/",
            },
            "TableType": "EXTERNAL_TABLE",
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=database_name, Name=table_name))

    database_arn = f"arn:aws:glue:{ctx.region}:{_account_id(ctx)}:database/{database_name}"
    return database_arn, database_name, table_name


def _error_code(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected rejection, but call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
