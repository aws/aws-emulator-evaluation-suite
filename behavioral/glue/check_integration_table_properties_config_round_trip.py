"""integration-table-properties-config-round-trip."""
from __future__ import annotations

import botocore

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "integration-table-properties-config-round-trip"
GROUP = "overly-permissive"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A target config written under a table ARN returns 200 yet reads back EntityNotFoundException;
    the same config under the parent database ARN reads back intact. SourceTableConfig is rejected
    with ValidationException (source support is documented as not yet implemented).
    """
    glue = ctx.client("glue")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # --- positive control: a target-config write addressed by the database ARN round-trips,
    # so the negative below cannot pass merely because the service is broken outright.
    control_db = ctx.unique_name("sim2real-itp-ctrldb-")
    glue.create_database(DatabaseInput={"Name": control_db}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=control_db))
    control_arn = f"arn:aws:glue:{ctx.region}:{account_id}:database/{control_db}"
    control_table_name = ctx.unique_name("sim2real-itp-ctrl-")
    control_config = {"UnnestSpec": "TOPLEVEL", "TargetTableName": "target_control"}

    glue.create_integration_table_properties(
        ResourceArn=control_arn, TableName=control_table_name, TargetTableConfig=control_config,
    )
    ctx.on_cleanup(
        lambda: _delete_itp_ignore_errors(glue, control_arn, control_table_name)
    )
    control_got = glue.get_integration_table_properties(ResourceArn=control_arn, TableName=control_table_name)
    control_target_cfg = control_got["TargetTableConfig"]
    assert control_target_cfg["UnnestSpec"] == control_config["UnnestSpec"], (
        f"positive control: UnnestSpec mismatch {control_target_cfg['UnnestSpec']!r} != {control_config['UnnestSpec']!r}"
    )
    assert control_target_cfg["TargetTableName"] == control_config["TargetTableName"], (
        f"positive control: TargetTableName mismatch "
        f"{control_target_cfg['TargetTableName']!r} != {control_config['TargetTableName']!r}"
    )

    # --- break exactly one thing: address the write by the table's own ARN instead of its
    # parent database's ARN.
    db_name = ctx.unique_name("sim2real-itp-db-")
    tbl_name = ctx.unique_name("sim2real-itp-tbl-")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    glue.create_table(DatabaseName=db_name, TableInput={"Name": tbl_name})
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=tbl_name))

    table_arn = f"arn:aws:glue:{ctx.region}:{account_id}:table/{db_name}/{tbl_name}"
    database_arn = f"arn:aws:glue:{ctx.region}:{account_id}:database/{db_name}"

    # TargetTableName only accepts a plain SQL-style identifier (letters/digits/underscores) --
    # hyphens are rejected with ValidationException ("Target Table Name contains invalid
    # characters").
    target_table_name = "target_" + tbl_name.replace("-", "_")
    target_config = {
        "UnnestSpec": "FULL",
        "TargetTableName": target_table_name,
        "PartitionSpec": [
            {"FieldName": "created_at", "FunctionSpec": "day", "ConversionSpec": "iso"},
        ],
    }
    itp_table_name = ctx.unique_name("sim2real-itp-")

    glue.create_integration_table_properties(
        ResourceArn=table_arn, TableName=itp_table_name, TargetTableConfig=target_config,
    )
    ctx.on_cleanup(lambda: _delete_itp_ignore_errors(glue, table_arn, itp_table_name))

    # The write is an orphan: an independent read on the exact same (ResourceArn, TableName)
    # pair 404s even though Create reported success.
    orphaned_code, orphaned_message = _error(
        lambda: glue.get_integration_table_properties(ResourceArn=table_arn, TableName=itp_table_name)
    )
    assert orphaned_code == "EntityNotFoundException", (
        f"expected EntityNotFoundException reading back a table-ARN-addressed write, got {orphaned_code!r}"
    )
    expected = (
        "Failed to find the sourceTableProperties with sourceArn "
        f"{table_arn} and tableName {itp_table_name}"
    )
    assert orphaned_message == expected, f"expected message {expected!r}, got {orphaned_message!r}"

    # --- restore: hold TableName fixed, correct only ResourceArn to the parent database ARN.
    glue.create_integration_table_properties(
        ResourceArn=database_arn, TableName=itp_table_name, TargetTableConfig=target_config,
    )
    ctx.on_cleanup(lambda: _delete_itp_ignore_errors(glue, database_arn, itp_table_name))
    restored = glue.get_integration_table_properties(ResourceArn=database_arn, TableName=itp_table_name)
    assert restored["TargetTableConfig"] == target_config, (
        f"restore: TargetTableConfig mismatch {restored['TargetTableConfig']!r} != {target_config!r}"
    )

    # --- unrelated negative: supplying SourceTableConfig at all is rejected outright (feature
    # not yet implemented on real AWS) -- exercised against a genuine Connection ARN, since
    # that is the documented ResourceArn shape for the (unsupported) source leg.
    conn_name = ctx.unique_name("sim2real-itp-conn-")
    glue.create_connection(
        ConnectionInput={
            "Name": conn_name,
            "ConnectionType": "JDBC",
            "ConnectionProperties": {
                "JDBC_CONNECTION_URL": "jdbc:mysql://sim2real.example.invalid:3306/sim2real",
                "USERNAME": "sim2real",
                "PASSWORD": "sim2real-placeholder",
            },
        },
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_connection(ConnectionName=conn_name))
    connection_arn = f"arn:aws:glue:{ctx.region}:{account_id}:connection/{conn_name}"

    other_table_name = ctx.unique_name("sim2real-src2-")
    source_code, source_message = _error(
        lambda: glue.create_integration_table_properties(
            ResourceArn=connection_arn,
            TableName=other_table_name,
            SourceTableConfig={
                "FilterPredicate": "id > 100",
                "PrimaryKey": ["id"],
                "RecordUpdateField": "updated_at",
            },
        )
    )
    assert source_code == "ValidationException", (
        f"expected ValidationException rejecting SourceTableConfig, got {source_code!r}"
    )
    expected = "Unsupported source table properties are provided."
    assert source_message == expected, f"expected message {expected!r}, got {source_message!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; an unexpected
    success raises."""
    try:
        result = fn()
    except botocore.exceptions.ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _delete_itp_ignore_errors(glue, resource_arn, table_name):
    try:
        glue.delete_integration_table_properties(ResourceArn=resource_arn, TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "EntityNotFoundException",
            "ResourceNotFoundException",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
