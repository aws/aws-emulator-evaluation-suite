"""create-configured-table-analysis-rule-duplicate-conflict."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-configured-table-analysis-rule-duplicate-conflict"
GROUP = "error-semantics"
SERVICES = ["cleanrooms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second LIST analysis rule on a configured table fails with ValidationException and the exact
    one-rule-per-table message and leaves the original policy unchanged; after a delete, the new policy
    is created and reads back."""
    glue = ctx.client("glue")
    cr = ctx.client("cleanrooms")

    db_name, table_name = _create_glue_table(ctx, glue)

    configured_table = cr.create_configured_table(
        name=ctx.unique_name("sim2real-cr-table-"),
        tableReference={"glue": {"tableName": table_name, "databaseName": db_name}},
        allowedColumns=["id", "value"],
        analysisMethod="DIRECT_QUERY",
        tags={"sim2real": CHECK},
    )["configuredTable"]
    table_id = configured_table["id"]
    ctx.on_cleanup(lambda: cr.delete_configured_table(configuredTableIdentifier=table_id))

    policy_v1 = {"list": {"joinColumns": ["id"], "listColumns": ["value"]}}
    cr.create_configured_table_analysis_rule(
        configuredTableIdentifier=table_id,
        analysisRuleType="LIST",
        analysisRulePolicy={"v1": policy_v1},
    )
    ctx.on_cleanup(lambda: cr.delete_configured_table_analysis_rule(
        configuredTableIdentifier=table_id, analysisRuleType="LIST"))

    error = _error(lambda: cr.create_configured_table_analysis_rule(
        configuredTableIdentifier=table_id,
        analysisRuleType="LIST",
        analysisRulePolicy={"v1": {"list": {"joinColumns": ["value"], "listColumns": ["id"]}}},
    ))
    assert error["Code"] == "ValidationException", error
    assert error["Message"] == (
        "Only one Analysis Rule is allowed per Configured Table "
        f"Configured Table {table_id} already has a LIST analysis rule."
    ), error

    still = cr.get_configured_table_analysis_rule(
        configuredTableIdentifier=table_id, analysisRuleType="LIST"
    )["analysisRule"]
    assert still["policy"]["v1"]["list"]["listColumns"] == ["value"], still["policy"]

    # Positive control: deleting then recreating the rule succeeds.
    cr.delete_configured_table_analysis_rule(configuredTableIdentifier=table_id, analysisRuleType="LIST")
    cr.create_configured_table_analysis_rule(
        configuredTableIdentifier=table_id,
        analysisRuleType="LIST",
        analysisRulePolicy={"v1": {"list": {"joinColumns": ["value"], "listColumns": ["id"]}}},
    )
    persisted = cr.get_configured_table_analysis_rule(
        configuredTableIdentifier=table_id, analysisRuleType="LIST"
    )["analysisRule"]
    assert persisted["policy"]["v1"]["list"]["listColumns"] == ["id"], persisted["policy"]


def _create_glue_table(ctx, glue):
    db_name = ctx.unique_name("sim2real_cr_db_").replace("-", "_")
    table_name = "cr_table"
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Columns": [{"Name": "id", "Type": "string"}, {"Name": "value", "Type": "string"}],
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


def _error(fn):
    """Call fn(); return its botocore Error dict (Code, Message). An unexpected SUCCESS
    raises, so an emulator accepting what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
