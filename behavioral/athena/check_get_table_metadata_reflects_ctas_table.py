"""get-table-metadata-reflects-ctas-table."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-table-metadata-reflects-ctas-table"
GROUP = "data-plane-depth"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetTableMetadata reports the columns and types of a table created via CTAS,
    matching exactly what the CTAS statement projected."""
    bucket = _make_output_bucket(ctx)
    athena = ctx.client("athena")
    out = f"s3://{bucket}/out/"
    db = ctx.unique_name("sim2real_athena_metadb_").replace("-", "_")
    tbl = ctx.unique_name("sim2real_athena_mtbl_").replace("-", "_")

    qid = athena.start_query_execution(
        QueryString=f"CREATE DATABASE {db} LOCATION 's3://{bucket}/db/'",
        ResultConfiguration={"OutputLocation": out},
    )["QueryExecutionId"]
    created_db = _wait_for_query(ctx, qid)
    assert created_db["Status"]["State"] == "SUCCEEDED", created_db["Status"]

    def _drop_db():
        _wait_for_query(
            ctx,
            athena.start_query_execution(
                QueryString=f"DROP DATABASE {db} CASCADE",
                ResultConfiguration={"OutputLocation": out},
            )["QueryExecutionId"],
        )

    ctx.on_cleanup(_drop_db)

    ctas_sql = (
        f"CREATE TABLE {db}.{tbl} "
        f"WITH (format='PARQUET', external_location='s3://{bucket}/ctas/{tbl}/') "
        "AS SELECT 7 AS quantity, 'widget' AS label"
    )
    qid2 = athena.start_query_execution(
        QueryString=ctas_sql, ResultConfiguration={"OutputLocation": out}
    )["QueryExecutionId"]
    ctas_exec = _wait_for_query(ctx, qid2)
    assert ctas_exec["Status"]["State"] == "SUCCEEDED", ctas_exec["Status"]

    meta = athena.get_table_metadata(
        CatalogName="AwsDataCatalog", DatabaseName=db, TableName=tbl
    )["TableMetadata"]
    assert meta["Name"] == tbl, meta["Name"]
    assert meta["TableType"] == "EXTERNAL_TABLE", meta["TableType"]
    cols = {c["Name"]: c["Type"].lower() for c in meta["Columns"]}
    assert "int" in cols["quantity"], cols
    assert "string" in cols["label"] or "varchar" in cols["label"], cols


def _make_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-out-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": CHECK},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=bucket)
        objs = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
        while objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
            resp = s3.list_objects_v2(Bucket=bucket)
            objs = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _wait_for_query(ctx, qid, timeout_s=180.0, interval_s=2.0):
    athena = ctx.client("athena")
    terminal = {"SUCCEEDED", "FAILED", "CANCELLED"}
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = athena.get_query_execution(QueryExecutionId=qid)
        last = resp["QueryExecution"]
        if last["Status"]["State"] in terminal:
            return last
        time.sleep(interval_s)
    state = last["Status"]["State"] if last else None
    raise AssertionError(f"query {qid} did not reach terminal state within {timeout_s}s (last={state})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
