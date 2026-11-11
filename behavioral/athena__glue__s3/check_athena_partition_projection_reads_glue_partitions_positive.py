"""athena-partition-projection-reads-glue-partitions-positive."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "athena-partition-projection-reads-glue-partitions-positive"
GROUP = "metastore-binding"
SERVICES = ["athena", "glue", "s3"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Athena reads exactly the S3 rows registered as Glue partitions via batch_create_partition."""
    bucket = _create_bucket(ctx)
    db = _sql_name(ctx, "sim2real_ga_part_db_")
    table = _sql_name(ctx, "part_tbl_")
    _create_glue_database(ctx, db)
    base_location = f"s3://{bucket}/data/"
    _put_text(ctx, bucket, "data/dt=2024-01-01/part.csv", "1,a\n2,b\n")
    _put_text(ctx, bucket, "data/dt=2024-01-02/part.csv", "3,c\n")

    columns = [{"Name": "id", "Type": "bigint"}, {"Name": "val", "Type": "string"}]
    partition_keys = [{"Name": "dt", "Type": "string"}]
    _create_csv_table(ctx, db, table, base_location, columns, partition_keys=partition_keys)

    glue = ctx.client("glue")
    partition_inputs = []
    for dt in ("2024-01-01", "2024-01-02"):
        sd = _csv_storage_descriptor(f"s3://{bucket}/data/dt={dt}/", columns)
        partition_inputs.append({"Values": [dt], "StorageDescriptor": sd})
    resp = glue.batch_create_partition(DatabaseName=db, TableName=table, PartitionInputList=partition_inputs)
    assert not resp.get("Errors"), resp.get("Errors")

    athena = ctx.client("athena")
    output = f"s3://{bucket}/athena-results/"

    # Query scoped to a single partition must return only that partition's rows.
    qid, state, reason = _run_query(
        athena,
        f"SELECT id, val FROM {db}.{table} WHERE dt = '2024-01-01' ORDER BY id",
        db,
        output,
    )
    assert state == "SUCCEEDED", f"query failed: state={state} reason={reason}"
    rows = _select_rows(athena, qid)
    assert rows == [["1", "a"], ["2", "b"]], f"expected [['1','a'],['2','b']], got {rows}"

    # Unfiltered query must see rows from both registered partitions.
    qid2, state2, reason2 = _run_query(athena, f"SELECT id FROM {db}.{table}", db, output)
    assert state2 == "SUCCEEDED", f"query failed: state={state2} reason={reason2}"
    all_rows = _select_rows(athena, qid2)
    assert sorted(int(r[0]) for r in all_rows) == [1, 2, 3], f"expected [1,2,3], got {all_rows}"


def _sql_name(ctx: Any, prefix: str) -> str:
    return ctx.unique_name(prefix).replace("-", "_").lower()


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-ga-").lower()
    # us-east-1 rejects CreateBucketConfiguration outright; every other region requires it.
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


def _create_csv_table(
    ctx: Any, db: str, table: str, location: str, columns: list, partition_keys: list | None = None
) -> str:
    glue = ctx.client("glue")
    table_input = {
        "Name": table,
        "TableType": "EXTERNAL_TABLE",
        "StorageDescriptor": _csv_storage_descriptor(location, columns),
        "Parameters": {"EXTERNAL": "TRUE"},
    }
    if partition_keys:
        table_input["PartitionKeys"] = partition_keys
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
