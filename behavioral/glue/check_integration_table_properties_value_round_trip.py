"""integration-table-properties-value-round-trip."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "integration-table-properties-value-round-trip"
GROUP = "representation"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Nested source/target property maps written via CreateIntegrationTableProperties
    come back byte-identical via GetIntegrationTableProperties."""
    glue = ctx.client("glue")
    resource_arn, database_name, table_name = _create_glue_table(ctx)

    # NOTE: CreateIntegrationTableProperties currently only supports target-table
    # configuration -- per the API docs, source-side config (via a connection ARN) "is
    # not yet implemented", and setting both Source and Target on the same call is
    # rejected with ValidationException ("Source and Target config can't both be set.").
    # Empirically (not per the docs' literal wording), ResourceArn for target-table
    # properties must be the *database* ARN that contains the target table, not the
    # table ARN itself -- passing the table ARN 404s on Get ("Failed to find the
    # sourceTableProperties...") even though Create appears to succeed.
    target_table_config = {
        "PartitionSpec": [
            {"FieldName": "updated_at", "FunctionSpec": "month", "ConversionSpec": "epoch_milli"},
            {"FieldName": "region", "FunctionSpec": "identity"},
        ],
        "TargetTableName": table_name,
        "UnnestSpec": "TOPLEVEL",
    }

    glue.create_integration_table_properties(
        ResourceArn=resource_arn,
        TableName=table_name,
        TargetTableConfig=target_table_config,
    )
    ctx.on_cleanup(
        lambda: glue.delete_integration_table_properties(
            ResourceArn=resource_arn, TableName=table_name
        )
    )

    fetched = glue.get_integration_table_properties(ResourceArn=resource_arn, TableName=table_name)

    assert fetched["TargetTableConfig"] == target_table_config, (
        f"TargetTableConfig mismatch: {fetched['TargetTableConfig']!r} != {target_table_config!r}"
    )


def _create_glue_table(ctx) -> tuple[str, str, str]:
    """Create a throwaway Glue database + table and return (database_arn, db_name, table_name)."""
    glue = ctx.client("glue")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    database_name = ctx.unique_name("sim2real_itp_db_").replace("-", "_").lower()
    glue.create_database(DatabaseInput={"Name": database_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=database_name))

    table_name = ctx.unique_name("sim2real_itp_tbl_").replace("-", "_").lower()
    glue.create_table(
        DatabaseName=database_name,
        TableInput={
            "Name": table_name,
            "StorageDescriptor": {
                "Columns": [
                    {"Name": "id", "Type": "string"},
                    {"Name": "customer_name", "Type": "string"},
                    {"Name": "order_amount", "Type": "double"},
                    {"Name": "region", "Type": "string"},
                    {"Name": "updated_at", "Type": "timestamp"},
                ],
                "Location": f"s3://sim2real-behavioral-test-bucket/{database_name}/{table_name}/",
            },
            "TableType": "EXTERNAL_TABLE",
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=database_name, Name=table_name))

    database_arn = f"arn:aws:glue:{ctx.region}:{account_id}:database/{database_name}"
    return database_arn, database_name, table_name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
