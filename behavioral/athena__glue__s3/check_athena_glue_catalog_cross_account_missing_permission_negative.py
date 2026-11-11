"""athena-glue-catalog-cross-account-missing-permission-negative."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "athena-glue-catalog-cross-account-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["athena", "glue", "s3"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A query against a `GLUE` data catalog registered for a foreign account that grants us nothing
    FAILS with Glue's GetDatabase access denial and has no results, while the same query shape
    against our own Glue catalog succeeds.

    Reference: https://docs.aws.amazon.com/athena/latest/ug/security-iam-cross-account-glue-catalog-access.html
    """
    caller = ctx.client("sts").get_caller_identity()
    account_id = caller["Account"]
    foreign_id = _foreign_account_id(account_id)

    bucket = _create_bucket(ctx)
    output = f"s3://{bucket}/athena-results/"
    athena = ctx.client("athena")

    catalog_name = ctx.unique_name("sim2real_ga_xacct_").replace("-", "_").lower()
    athena.create_data_catalog(
        Name=catalog_name,
        Type="GLUE",
        Parameters={"catalog-id": foreign_id},
        Description="sim2real cross-account negative check",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: athena.delete_data_catalog(Name=catalog_name))

    # Negative: no resource policy on the foreign account's Glue catalog grants us anything, so
    # even resolving a database in that catalog must be denied -- regardless of whether the
    # database/table names below exist there.
    qid_bad, state_bad, reason_bad = _run_query(
        athena,
        "SELECT * FROM some_db.some_table LIMIT 1",
        None,
        output,
        catalog=catalog_name,
    )
    assert state_bad == "FAILED", f"expected FAILED, got {state_bad} (reason={reason_bad})"
    # Athena reports the Glue denial verbatim, naming the caller and the foreign catalog; the
    # message ends in a space.
    expected_reason = (
        f"Insufficient permissions to execute the query. User: {caller['Arn']} is not authorized "
        f"to perform: glue:GetDatabase on resource: arn:aws:glue:{ctx.region}:{foreign_id}:catalog "
        "because no resource-based policy allows the glue:GetDatabase action "
    )
    assert reason_bad == expected_reason, reason_bad

    # The effect is absent: the denied execution never produced a retrievable result set.
    code, message = _error_code(lambda: athena.get_query_results(QueryExecutionId=qid_bad))
    assert code == "InvalidRequestException", code
    assert message == "Query did not finish successfully. Final query state: FAILED", message

    # Positive control: the identical query shape against our OWN Glue catalog (no cross-account
    # boundary involved) succeeds, proving the rejection above is about the foreign catalog-id and
    # not a general wiring failure.
    db = _sql_name(ctx, "sim2real_ga_xacct_db_")
    table = _sql_name(ctx, "xacct_tbl_")
    _create_glue_database(ctx, db)
    location = f"s3://{bucket}/data/{table}/"
    _put_text(ctx, bucket, f"data/{table}/part.csv", "1,local\n")
    columns = [{"Name": "id", "Type": "bigint"}, {"Name": "val", "Type": "string"}]
    _create_csv_table(ctx, db, table, location, columns)

    qid_ok, state_ok, reason_ok = _run_query(athena, f"SELECT id, val FROM {db}.{table}", db, output)
    assert state_ok == "SUCCEEDED", f"control query failed: state={state_ok} reason={reason_ok}"
    assert _select_rows(athena, qid_ok) == [["1", "local"]]




def _foreign_account_id(own_account_id: str) -> str:
    """A syntactically valid 12-digit account id guaranteed to differ from our own."""
    digits = list(own_account_id)
    digits[0] = str((int(digits[0]) + 1) % 10)
    candidate = "".join(digits)
    if candidate == own_account_id:
        digits[1] = str((int(digits[1]) + 1) % 10)
        candidate = "".join(digits)
    return candidate


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
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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
    glue.create_database(DatabaseInput={"Name": name}, Tags={"sim2real": CHECK})
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


def _run_query(
    athena,
    sql: str,
    database: str | None,
    output_location: str,
    timeout_s: float = 90.0,
    catalog: str | None = None,
):
    kwargs: dict[str, Any] = {"QueryString": sql, "ResultConfiguration": {"OutputLocation": output_location}}
    if database or catalog:
        ctx_dict: dict[str, Any] = {}
        if database:
            ctx_dict["Database"] = database
        if catalog:
            ctx_dict["Catalog"] = catalog
        kwargs["QueryExecutionContext"] = ctx_dict
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
