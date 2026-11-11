"""deploy-database-via-cloudformation."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-database-via-cloudformation"
GROUP = "deploy"
SERVICES = ["glue"]

_STACK_TERMINAL = {
    "CREATE_COMPLETE",
    "CREATE_FAILED",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "DELETE_COMPLETE",
}


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::Glue::Database is genuinely usable: GetDatabase
    reflects the templated Description/LocationUri/Parameters, and a real table can be
    created inside it via the Glue API (not merely CREATE_COMPLETE on the stack)."""
    glue = ctx.client("glue")

    db_name = ctx.unique_name("sim2real_glue_db_").replace("-", "_")
    description = "sim2real glue behavioral fidelity test database"
    location_uri = f"s3://sim2real-glue-behavioral-nonexistent/{db_name}/"

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "DatabaseName": {"Type": "String"},
            "DatabaseDescription": {"Type": "String"},
            "DatabaseLocationUri": {"Type": "String"},
        },
        "Resources": {
            "GlueDatabase": {
                "Type": "AWS::Glue::Database",
                "Properties": {
                    "CatalogId": {"Ref": "AWS::AccountId"},
                    "DatabaseInput": {
                        "Name": {"Ref": "DatabaseName"},
                        "Description": {"Ref": "DatabaseDescription"},
                        "LocationUri": {"Ref": "DatabaseLocationUri"},
                        "Parameters": {"classification": "test", "sim2real": "true"},
                    },
                },
            }
        },
    }
    _deploy_stack(
        ctx,
        template,
        {
            "DatabaseName": db_name,
            "DatabaseDescription": description,
            "DatabaseLocationUri": location_uri,
        },
    )

    database = glue.get_database(Name=db_name)["Database"]
    assert database["Name"] == db_name, f"expected database name {db_name!r}, got {database['Name']!r}"
    assert database["Description"] == description, (
        f"CFN-templated Description did not reach the Glue catalog: "
        f"expected {description!r}, got {database['Description']!r}"
    )
    assert database["LocationUri"] == location_uri, (
        f"CFN-templated LocationUri did not reach the Glue catalog: "
        f"expected {location_uri!r}, got {database['LocationUri']!r}"
    )
    assert database["Parameters"]["classification"] == "test", (
        f"CFN-templated Parameters.classification did not reach the Glue catalog: "
        f"expected 'test', got {database['Parameters'].get('classification')!r}"
    )
    assert database["Parameters"]["sim2real"] == "true", (
        f"CFN-templated Parameters.sim2real did not reach the Glue catalog: "
        f"expected 'true', got {database['Parameters'].get('sim2real')!r}"
    )

    table_name = ctx.unique_name("sim2real_glue_tbl_").replace("-", "_")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Columns": [
                    {"Name": "id", "Type": "int"},
                    {"Name": "name", "Type": "string"},
                ],
                "Location": f"{location_uri}data/",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe"
                },
            },
        },
    )
    ctx.on_cleanup(lambda: _delete_table_if_present(glue, db_name, table_name))

    table = glue.get_table(DatabaseName=db_name, Name=table_name)["Table"]
    assert table["Name"] == table_name, f"expected table name {table_name!r}, got {table['Name']!r}"
    assert table["DatabaseName"] == db_name, (
        f"expected table's DatabaseName to be {db_name!r}, got {table['DatabaseName']!r}"
    )
    column_names = [c["Name"] for c in table["StorageDescriptor"]["Columns"]]
    assert column_names == ["id", "name"], f"expected columns ['id', 'name'], got {column_names!r}"

    tables = glue.get_tables(DatabaseName=db_name)["TableList"]
    assert any(t["Name"] == table_name for t in tables), (
        f"table {table_name!r} did not appear in get_tables for database {db_name!r}"
    )

    # The table is already scheduled for on_cleanup deletion -- make that delete a free
    # negative assertion instead of an unasserted teardown.
    glue.delete_table(DatabaseName=db_name, Name=table_name)
    try:
        glue.get_table(DatabaseName=db_name, Name=table_name)
    except ClientError as e:
        err = e.response.get("Error", {})
        refusal = (err.get("Code"), err.get("Message"))
        assert refusal == ("EntityNotFoundException", "Entity Not Found"), (
            f"expected EntityNotFoundException reading a deleted table, got {refusal!r}"
        )
    else:
        raise AssertionError(f"get_table succeeded for {table_name!r} after it was deleted")

    tables_after_delete = glue.get_tables(DatabaseName=db_name)["TableList"]
    assert not any(t["Name"] == table_name for t in tables_after_delete), (
        f"deleted table {table_name!r} still appears in get_tables for database {db_name!r}"
    )


def _delete_table_if_present(glue, db_name: str, table_name: str) -> None:
    try:
        glue.delete_table(DatabaseName=db_name, Name=table_name)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "EntityNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _stack_status(cfn, stack_name: str) -> str:
    try:
        resp = cfn.describe_stacks(StackName=stack_name)
        return resp["Stacks"][0]["StackStatus"]
    except ClientError as e:
        if "does not exist" in str(e):
            return "DELETE_COMPLETE"
        raise


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    _poll_until(
        lambda: _stack_status(cfn, stack_name),
        lambda s: s == "DELETE_COMPLETE",
        timeout_s=300.0,
        interval_s=10.0,
    )


def _deploy_stack(ctx, template: dict, params: dict) -> str:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-glue-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in params.items()],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    status = _poll_until(
        lambda: _stack_status(cfn, stack_name),
        lambda s: s in _STACK_TERMINAL,
        timeout_s=300.0,
        interval_s=10.0,
    )
    if status != "CREATE_COMPLETE":
        raise AssertionError(f"stack {stack_name} did not reach CREATE_COMPLETE (status={status})")
    return stack_name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
