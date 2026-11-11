"""glue-catalog-table-location-points-to-s3-positive."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "glue-catalog-table-location-points-to-s3-positive"
GROUP = "resource-binding"
SERVICES = ["athena", "glue", "s3"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An Athena query on a Glue catalog table returns exactly the rows stored at the table's S3
    Location, so the Location resolves to a readable prefix rather than being a stored string."""
    s3 = ctx.client("s3")
    glue = ctx.client("glue")
    athena = ctx.client("athena")

    bucket = ctx.unique_name("sim2real-catloc-")
    _create_bucket(ctx, s3, bucket)
    data_prefix = "data/"
    rows = [b"1,alice\n", b"2,bob\n", b"3,carol\n"]
    s3.put_object(Bucket=bucket, Key=f"{data_prefix}rows.csv", Body=b"".join(rows))

    db_name = ctx.unique_name("sim2real_catloc_db_").replace("-", "_").lower()
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    table_name = ctx.unique_name("sim2real_catloc_tbl_").replace("-", "_").lower()
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "Parameters": {"classification": "csv"},
            "StorageDescriptor": {
                "Columns": [{"Name": "id", "Type": "int"}, {"Name": "name", "Type": "string"}],
                "Location": f"s3://{bucket}/{data_prefix}",
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

    fetched_location = glue.get_table(DatabaseName=db_name, Name=table_name)["Table"]["StorageDescriptor"]["Location"]
    expected_location = f"s3://{bucket}/{data_prefix}"
    assert fetched_location.rstrip("/") == expected_location.rstrip("/"), (
        f"expected catalog Location {expected_location!r}, got {fetched_location!r}"
    )

    result_location = f"s3://{bucket}/athena-results/"
    exec_id = athena.start_query_execution(
        QueryString=f"SELECT COUNT(*) AS cnt FROM {db_name}.{table_name}",
        QueryExecutionContext={"Database": db_name},
        ResultConfiguration={"OutputLocation": result_location},
    )["QueryExecutionId"]

    state, reason = _wait_for_query(athena, exec_id, timeout_s=120)
    assert state == "SUCCEEDED", f"Athena query against the catalog table failed: state={state!r} reason={reason!r}"

    results = athena.get_query_results(QueryExecutionId=exec_id)
    data_rows = results["ResultSet"]["Rows"]
    # Rows[0] is the header ("cnt"); Rows[1] holds the aggregate value.
    count_value = int(data_rows[1]["Data"][0]["VarCharValue"])
    assert count_value == len(rows), f"expected Athena to see {len(rows)} rows via the catalog Location, got {count_value}"


def _create_bucket(ctx, s3, name: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))


def _empty_and_delete_bucket(s3, name: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            s3.delete_objects(Bucket=name, Delete={"Objects": objs})
    s3.delete_bucket(Bucket=name)


def _wait_for_query(athena, exec_id: str, timeout_s: int = 120):
    terminal = {"SUCCEEDED", "FAILED", "CANCELLED"}
    deadline = time.monotonic() + timeout_s
    state, reason = None, None
    while time.monotonic() < deadline:
        status = athena.get_query_execution(QueryExecutionId=exec_id)["QueryExecution"]["Status"]
        state = status["State"]
        reason = status.get("StateChangeReason")
        if state in terminal:
            return state, reason
        time.sleep(3)
    raise AssertionError(f"query {exec_id} did not reach a terminal state within {timeout_s}s (last={state!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
