"""get-query-results-data-manifest-type-unload-vs-select."""
from __future__ import annotations

import time
from urllib.parse import urlparse

from behavioral_harness import tags


CHECK = "get-query-results-data-manifest-type-unload-vs-select"
GROUP = "state"
SERVICES = ["athena"]


def _create_result_bucket(ctx):
    """An S3 bucket Athena writes query results and UNLOAD output into."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-athena-manifest-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _wait_terminal(athena, qid, timeout_s=90.0):
    terminal = {"SUCCEEDED", "FAILED", "CANCELLED"}
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
        if last["Status"]["State"] in terminal:
            return last
        time.sleep(2.0)
    raise AssertionError(f"query {qid} did not reach a terminal state: {last}")


def _error(fn):
    """Call fn() and return its ClientError (code, message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """GetQueryResults(QueryResultType=DATA_MANIFEST) lists the S3 objects an UNLOAD query wrote,
    an independent read of the object that exists, but refuses a query type that writes no
    manifest with the exact reason and the refused query's own id."""
    bucket = _create_result_bucket(ctx)
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    out = f"s3://{bucket}/results/"
    unload_prefix = "unloaded/"

    unload_qid = athena.start_query_execution(
        QueryString=f"UNLOAD (SELECT 1 AS col) TO 's3://{bucket}/{unload_prefix}' WITH (format = 'JSON')",
        ResultConfiguration={"OutputLocation": out},
    )["QueryExecutionId"]
    unload_qe = _wait_terminal(athena, unload_qid)
    assert unload_qe["Status"]["State"] == "SUCCEEDED", (
        f"expected the UNLOAD to reach SUCCEEDED, got {unload_qe['Status']}"
    )

    manifest = athena.get_query_results(QueryExecutionId=unload_qid, QueryResultType="DATA_MANIFEST")
    manifest_rows = manifest["ResultSet"]["Rows"]
    assert len(manifest_rows) == 1, (
        f"expected the single-file UNLOAD's manifest to list exactly one row, got {manifest_rows!r}"
    )
    assert manifest["ResultSet"]["ResultSetMetadata"]["ColumnInfo"] == [], (
        "a manifest listing is not tabular data, so it must carry no ColumnInfo, got "
        f"{manifest['ResultSet']['ResultSetMetadata']['ColumnInfo']!r}"
    )
    manifest_uri = manifest_rows[0]["Data"][0]["VarCharValue"]
    parsed = urlparse(manifest_uri)
    assert parsed.scheme == "s3" and parsed.netloc == bucket, (
        f"expected the manifest entry to be an s3:// URI into {bucket!r}, got {manifest_uri!r}"
    )
    key = parsed.path.lstrip("/")
    assert key.startswith(unload_prefix), (
        f"expected the manifest entry's key to live under {unload_prefix!r}, got {key!r}"
    )
    # Independent read at the destination: the manifest names a real object UNLOAD wrote.
    head = s3.head_object(Bucket=bucket, Key=key)
    assert head["ContentLength"] > 0, (
        f"expected the manifest-listed object {key!r} to hold UNLOAD's output, got ContentLength "
        f"{head['ContentLength']!r}"
    )

    data = athena.get_query_results(QueryExecutionId=unload_qid, QueryResultType="DATA_ROWS")
    assert data["ResultSet"]["Rows"] == [], (
        f"UNLOAD sends its output to S3, so DATA_ROWS must stay empty, got {data['ResultSet']['Rows']!r}"
    )

    select_qid = athena.start_query_execution(
        QueryString="SELECT 1 AS col",
        ResultConfiguration={"OutputLocation": out},
    )["QueryExecutionId"]
    select_qe = _wait_terminal(athena, select_qid)
    assert select_qe["Status"]["State"] == "SUCCEEDED", (
        f"expected the plain SELECT to reach SUCCEEDED, got {select_qe['Status']}"
    )

    # Positive control: the same execution's default DATA_ROWS result still works.
    select_data = athena.get_query_results(QueryExecutionId=select_qid)
    assert select_data["ResultSet"]["Rows"][1]["Data"][0]["VarCharValue"] == "1", (
        f"expected the SELECT's data row to carry '1', got {select_data['ResultSet']['Rows']!r}"
    )

    code, message = _error(
        lambda: athena.get_query_results(QueryExecutionId=select_qid, QueryResultType="DATA_MANIFEST")
    )
    assert code == "InvalidRequestException", (
        f"expected InvalidRequestException for DATA_MANIFEST on a plain SELECT, got {code!r}"
    )
    assert message == (
        "Manifest files are only available for INSERT, CTAS (CREATE TABLE AS SELECT), and "
        f"UNLOAD queries. query {select_qid} does not generate a manifest file."
    ), f"unexpected GetQueryResults message for DATA_MANIFEST on a plain SELECT: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
