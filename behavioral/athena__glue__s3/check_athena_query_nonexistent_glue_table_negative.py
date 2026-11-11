"""athena-query-nonexistent-glue-table-negative."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "athena-query-nonexistent-glue-table-negative"
GROUP = "metastore-binding"
SERVICES = ["athena", "glue", "s3"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A query against a table absent from the Glue catalog fails (not silently binds), while a
    query against a real table in the same database (positive control) still succeeds."""
    bucket = _create_bucket(ctx)
    db = _sql_name(ctx, "sim2real_ga_neg_db_")
    real_table = _sql_name(ctx, "real_tbl_")
    missing_table = _sql_name(ctx, "missing_tbl_")
    _create_glue_database(ctx, db)

    location = f"s3://{bucket}/data/{real_table}/"
    _put_text(ctx, bucket, f"data/{real_table}/part.csv", "1,ok\n")
    columns = [{"Name": "id", "Type": "bigint"}, {"Name": "val", "Type": "string"}]
    _create_csv_table(ctx, db, real_table, location, columns)

    athena = ctx.client("athena")
    output = f"s3://{bucket}/athena-results/"

    # Positive control: the real table resolves via the Glue catalog and returns its row.
    qid_ok, state_ok, reason_ok = _run_query(
        athena, f"SELECT id, val FROM {db}.{real_table}", db, output
    )
    assert state_ok == "SUCCEEDED", f"control query failed: state={state_ok} reason={reason_ok}"
    rows_ok = _select_rows(athena, qid_ok)
    assert rows_ok == [["1", "ok"]], f"expected [['1', 'ok']], got {rows_ok}"

    # Negative: a table absent from the catalog must fail, not silently bind to something else.
    qid_bad, state_bad, reason_bad = _run_query(
        athena, f"SELECT * FROM {db}.{missing_table}", db, output
    )
    assert state_bad == "FAILED", f"expected FAILED, got {state_bad} (reason={reason_bad})"
    # Column 15 is where the table reference starts in the fixed SQL text above.
    assert reason_bad == (
        f"TABLE_NOT_FOUND: line 1:15: Table 'awsdatacatalog.{db}.{missing_table}' does not exist"
    ), reason_bad

    # The effect is absent: the failed execution has no retrievable result set.
    code, message = _error_code(lambda: athena.get_query_results(QueryExecutionId=qid_bad))
    assert code == "InvalidRequestException", code
    assert message == "Query did not finish successfully. Final query state: FAILED", message


def _sql_name(ctx: Any, prefix: str) -> str:
    return ctx.unique_name(prefix).replace("-", "_").lower()


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-ga-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    return bucket


def _empty_and_delete_bucket(ctx: Any, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            )
    s3.delete_bucket(Bucket=bucket)


def _put_text(ctx: Any, bucket: str, key: str, content: str) -> None:
    ctx.client("s3").put_object(Bucket=bucket, Key=key, Body=content.encode("utf-8"))


def _create_glue_database(ctx: Any, name: str) -> str:
    glue = ctx.client("glue")
    glue.create_database(DatabaseInput={"Name": name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=name))
    return name


def _csv_storage_descriptor(location: str, columns: list) -> dict:
    return {
        "Columns": columns,
        "Location": location,
        "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
        "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
        "SerdeInfo": {
            "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
            "Parameters": {"field.delim": ","},
        },
    }


def _create_csv_table(ctx: Any, db: str, table: str, location: str, columns: list) -> str:
    glue = ctx.client("glue")
    table_input = {
        "Name": table,
        "TableType": "EXTERNAL_TABLE",
        "StorageDescriptor": _csv_storage_descriptor(location, columns),
        "Parameters": {"EXTERNAL": "TRUE"},
    }
    glue.create_table(DatabaseName=db, TableInput=table_input)
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db, Name=table))
    return table


def _run_query(athena, sql: str, database: str | None, output_location: str, timeout_s: float = 90.0):
    kwargs: dict[str, Any] = {"QueryString": sql, "ResultConfiguration": {"OutputLocation": output_location}}
    if database:
        kwargs["QueryExecutionContext"] = {"Database": database}
    qid = athena.start_query_execution(**kwargs)["QueryExecutionId"]
    deadline = time.monotonic() + timeout_s
    state = None
    reason = None
    while time.monotonic() < deadline:
        resp = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
        state = resp["Status"]["State"]
        reason = resp["Status"].get("StateChangeReason")
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            return qid, state, reason
        time.sleep(1.5)
    raise AssertionError(f"query {qid} did not reach a terminal state within {timeout_s}s (last={state})")


def _select_rows(athena, qid: str) -> list:
    rows = []
    paginator = athena.get_paginator("get_query_results")
    for page in paginator.paginate(QueryExecutionId=qid):
        for row in page["ResultSet"]["Rows"]:
            rows.append([d.get("VarCharValue") for d in row["Data"]])
    return rows[1:]  # first row is the column header for SELECT statements


def _error_code(fn) -> tuple[str, str]:
    """fn()'s error code and message; a call that succeeds where a refusal is expected fails."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
