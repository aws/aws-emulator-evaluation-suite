"""update-configured-table-analysis-method-conflict-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-configured-table-analysis-method-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["cleanrooms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With a LIST analysis rule on "id" and "value", dropping the unreferenced "extra" column from allowedColumns
    succeeds but dropping "id" fails with ValidationException and the exact message and leaves the columns unchanged;
    after the rule is deleted, the same update succeeds."""
    glue = ctx.client("glue")
    cr = ctx.client("cleanrooms")

    db_name, table_name = _create_glue_table(ctx, glue)

    configured_table = cr.create_configured_table(
        name=ctx.unique_name("sim2real-cr-table-"),
        description="original description",
        tableReference={"glue": {"tableName": table_name, "databaseName": db_name}},
        allowedColumns=["id", "value", "extra"],
        analysisMethod="DIRECT_QUERY",
        tags={"sim2real-check": CHECK},
    )["configuredTable"]
    table_id = configured_table["id"]
    ctx.on_cleanup(lambda: cr.delete_configured_table(configuredTableIdentifier=table_id))

    cr.create_configured_table_analysis_rule(
        configuredTableIdentifier=table_id,
        analysisRuleType="LIST",
        analysisRulePolicy={"v1": {"list": {"joinColumns": ["id"], "listColumns": ["value"]}}},
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: cr.delete_configured_table_analysis_rule(
        configuredTableIdentifier=table_id, analysisRuleType="LIST")))

    # Positive control: the active rule references "id" and "value" only, so
    # dropping the unreferenced "extra" column still succeeds. Without this,
    # "rejects dropping id" is indistinguishable from "rejects every
    # allowedColumns update while a rule exists".
    cr.update_configured_table(configuredTableIdentifier=table_id, allowedColumns=["id", "value"])
    control = cr.get_configured_table(configuredTableIdentifier=table_id)["configuredTable"]
    assert sorted(control["allowedColumns"]) == ["id", "value"], (
        f"expected ['id', 'value'] after dropping the unreferenced column, got {control['allowedColumns']!r}")

    # Break: dropping "id" would strand the active rule's joinColumns reference to it.
    error = _client_error(lambda: cr.update_configured_table(
        configuredTableIdentifier=table_id, allowedColumns=["value"]
    ))
    assert error.get("Code") == "ValidationException", (
        f"expected ValidationException dropping a column referenced by the active rule, got {error!r}")
    assert error.get("Message") == (
        "The following columns in the analysis rule aren't present in the allowed columns list: [id]. "
        "To be used in the analysis rule, columns must be specified as allowed columns."
    ), error
    still = cr.get_configured_table(configuredTableIdentifier=table_id)["configuredTable"]
    assert sorted(still["allowedColumns"]) == ["id", "value"], (
        f"expected allowedColumns unchanged at ['id', 'value'] after the rejected update, got {still['allowedColumns']!r}")

    # Restore: delete the rule, then the identical update now succeeds.
    cr.delete_configured_table_analysis_rule(configuredTableIdentifier=table_id, analysisRuleType="LIST")
    cr.update_configured_table(configuredTableIdentifier=table_id, allowedColumns=["value"])
    restored = cr.get_configured_table(configuredTableIdentifier=table_id)["configuredTable"]
    assert restored["allowedColumns"] == ["value"], (
        f"expected allowedColumns == ['value'] once the blocking rule was removed, got {restored['allowedColumns']!r}")


def _create_glue_table(ctx, glue):
    db_name = ctx.unique_name("sim2real_cr_db_").replace("-", "_")
    table_name = "cr_table"
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Columns": [
                    {"Name": "id", "Type": "string"},
                    {"Name": "value", "Type": "string"},
                    {"Name": "extra", "Type": "string"},
                ],
                "Location": f"s3://sim2real-cleanrooms-placeholder/{db_name}/",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                    "Parameters": {"field.delim": ","},
                },
            },
        },
    )
    return db_name, table_name


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises, so a target
    that accepts input AWS refuses fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
