"""athena-query-reads-csv-data-from-s3-positive."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "athena-query-reads-csv-data-from-s3-positive"
GROUP = "data-source"
SERVICES = ["athena", "glue", "s3"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """An Athena query over a Glue table backed by S3 CSV files returns rows that
    match the underlying object content byte-for-byte (values, order, count)."""
    data_bucket = _create_bucket(ctx, "data")
    out_bucket = _create_bucket(ctx, "out")

    csv_body = "id,name,amount\n1,alpha,10.5\n2,beta,20.25\n3,gamma,30.75\n"
    s3 = ctx.client("s3")
    s3.put_object(Bucket=data_bucket, Key="table/data.csv", Body=csv_body.encode("utf-8"))

    db_name = _create_glue_database(ctx)
    table_name = _create_glue_csv_table(
        ctx,
        db_name,
        location=f"s3://{data_bucket}/table/",
        columns=[
            {"Name": "id", "Type": "int"},
            {"Name": "name", "Type": "string"},
            {"Name": "amount", "Type": "double"},
        ],
    )

    output_location = f"s3://{out_bucket}/results/"
    qid, state, exec_resp = _run_query(
        ctx,
        query=f"SELECT id, name, amount FROM {table_name} ORDER BY id",
        database=db_name,
        output_location=output_location,
    )
    assert state == "SUCCEEDED", f"query did not succeed: {exec_resp['Status']}"

    rows = ctx.client("athena").get_query_results(QueryExecutionId=qid)["ResultSet"]["Rows"]
    # header + exactly 3 data rows matching the source CSV content, in order.
    assert len(rows) == 4, f"expected header + 3 rows, got {len(rows)}"
    expected = [
        ["1", "alpha", "10.5"],
        ["2", "beta", "20.25"],
        ["3", "gamma", "30.75"],
    ]
    for row, exp in zip(rows[1:], expected):
        values = [c.get("VarCharValue") for c in row["Data"]]
        assert values == exp, f"row mismatch: {values} != {exp}"


def _create_bucket(ctx, kind: str) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name(f"sim2real-athena-{kind}-").replace("_", "-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
    s3.delete_bucket(Bucket=name)


def _create_glue_database(ctx) -> str:
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real_athena_db_").replace("-", "_").lower()
    glue.create_database(DatabaseInput={"Name": name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=name))
    return name


def _create_glue_csv_table(ctx, db_name: str, location: str, columns: list) -> str:
    glue = ctx.client("glue")
    table_name = ctx.unique_name("sim2real_athena_tbl_").replace("-", "_").lower()
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "Parameters": {"skip.header.line.count": "1", "classification": "csv"},
            "StorageDescriptor": {
                "Columns": columns,
                "Location": location,
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                    "Parameters": {"field.delim": ","},
                },
            },
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=table_name))
    return table_name


def _run_query(
    ctx,
    query: str,
    output_location: str | None = None,
    database: str | None = None,
    workgroup: str | None = None,
    timeout_s: float = 120.0,
):
    athena = ctx.client("athena")
    kwargs: dict = {"QueryString": query}
    if database:
        kwargs["QueryExecutionContext"] = {"Database": database}
    if output_location:
        kwargs["ResultConfiguration"] = {"OutputLocation": output_location}
    if workgroup:
        kwargs["WorkGroup"] = workgroup
    resp = athena.start_query_execution(**kwargs)
    qid = resp["QueryExecutionId"]
    deadline = time.monotonic() + timeout_s
    exec_resp = None
    state = None
    while time.monotonic() < deadline:
        exec_resp = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
        state = exec_resp["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            return qid, state, exec_resp
        time.sleep(2)
    raise AssertionError(f"query {qid} did not finish in {timeout_s}s, last state {state}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
