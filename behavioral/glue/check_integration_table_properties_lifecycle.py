"""integration-table-properties-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "integration-table-properties-lifecycle"
GROUP = "state-machine"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateIntegrationTableProperties -> GetIntegrationTableProperties reflects the source
    table config -> DeleteIntegrationTableProperties removes it and a subsequent get 404s."""
    glue = ctx.client("glue")
    account = _account_id(ctx)
    db_name = _create_database(ctx, glue)
    table_name = _create_table(ctx, glue, db_name)
    # Per the API docs, target-table properties are set using the *database* ARN as
    # ResourceArn (not the table ARN), with TableName naming the target table itself.
    resource_arn = f"arn:aws:glue:{ctx.region}:{account}:database/{db_name}"

    glue.create_integration_table_properties(
        ResourceArn=resource_arn,
        TableName=table_name,
        TargetTableConfig={"TargetTableName": table_name, "UnnestSpec": "TOPLEVEL"},
    )
    ctx.on_cleanup(lambda: _cleanup_table_properties(glue, resource_arn, table_name))

    got = glue.get_integration_table_properties(ResourceArn=resource_arn, TableName=table_name)
    assert got["TargetTableConfig"]["TargetTableName"] == table_name, (
        f"expected TargetTableName {table_name!r}, got {got['TargetTableConfig'].get('TargetTableName')!r}"
    )
    assert got["TargetTableConfig"]["UnnestSpec"] == "TOPLEVEL", (
        f"expected UnnestSpec 'TOPLEVEL', got {got['TargetTableConfig'].get('UnnestSpec')!r}"
    )

    glue.delete_integration_table_properties(ResourceArn=resource_arn, TableName=table_name)

    # The identifier is dead, not merely pending: a repeat Delete on the same
    # (ResourceArn, TableName) must also fail rather than silently no-op-succeeding.
    expected_message = f"The target resource {resource_arn} is not found."
    delete_code, delete_message = _error_code(
        lambda: glue.delete_integration_table_properties(ResourceArn=resource_arn, TableName=table_name)
    )
    assert delete_code == "EntityNotFoundException", (
        f"expected EntityNotFoundException on repeat Delete, got {delete_code!r}"
    )
    assert delete_message == expected_message, (
        f"expected repeat Delete message {expected_message!r}, got {delete_message!r}"
    )

    expected_message = f"The target resource {resource_arn} is not found."
    get_code, get_message = _error_code(
        lambda: glue.get_integration_table_properties(ResourceArn=resource_arn, TableName=table_name)
    )
    assert get_code == "EntityNotFoundException", (
        f"expected EntityNotFoundException on Get after delete, got {get_code!r}"
    )
    assert get_message == expected_message, (
        f"expected Get-after-delete message {expected_message!r}, got {get_message!r}"
    )


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_database(ctx, glue) -> str:
    db_name = ctx.unique_name("sim2real_behav_integtbl_db_")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: _cleanup_database(glue, db_name))
    return db_name


def _create_table(ctx, glue, db_name: str) -> str:
    table_name = ctx.unique_name("sim2real_behav_integtbl_tbl_")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "StorageDescriptor": {
                "Columns": [
                    {"Name": "id", "Type": "string"},
                    {"Name": "value", "Type": "string"},
                ],
                "Location": f"s3://sim2real-behav-bucket/{db_name}/{table_name}/",
            },
            "TableType": "EXTERNAL_TABLE",
        },
    )
    ctx.on_cleanup(lambda: _cleanup_table(glue, db_name, table_name))
    return table_name


def _cleanup_table_properties(glue, resource_arn: str, table_name: str) -> None:
    try:
        glue.delete_integration_table_properties(ResourceArn=resource_arn, TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "EntityNotFoundException",
            "ResourceNotFoundException",
        ):
            raise


def _cleanup_table(glue, db_name: str, table_name: str) -> None:
    try:
        glue.delete_table(DatabaseName=db_name, Name=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _cleanup_database(glue, db_name: str) -> None:
    try:
        glue.delete_database(Name=db_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
