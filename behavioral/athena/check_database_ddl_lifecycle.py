"""database-ddl-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "database-ddl-lifecycle"
GROUP = "state-machine"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CREATE DATABASE makes the database visible via GetDatabase/ListDatabases;
    DROP DATABASE removes it, after which GetDatabase reports MetadataException."""
    bucket = _make_output_bucket(ctx)
    athena = ctx.client("athena")
    out = f"s3://{bucket}/out/"
    db = ctx.unique_name("sim2real_athena_lcdb_").replace("-", "_")

    qid = athena.start_query_execution(
        QueryString=f"CREATE DATABASE {db} LOCATION 's3://{bucket}/db/'",
        ResultConfiguration={"OutputLocation": out},
    )["QueryExecutionId"]
    created = _wait_for_query(ctx, qid)
    assert created["Status"]["State"] == "SUCCEEDED", created["Status"]
    assert created["StatementType"] == "DDL", created["StatementType"]

    got = athena.get_database(CatalogName="AwsDataCatalog", DatabaseName=db)["Database"]
    assert got["Name"] == db, f"expected GetDatabase to reflect {db!r}, got {got['Name']!r}"

    names = [d["Name"] for d in athena.list_databases(CatalogName="AwsDataCatalog")["DatabaseList"]]
    assert db in names, f"expected {db!r} in ListDatabases, got {names!r}"

    qid2 = athena.start_query_execution(
        QueryString=f"DROP DATABASE {db}", ResultConfiguration={"OutputLocation": out}
    )["QueryExecutionId"]
    dropped = _wait_for_query(ctx, qid2)
    assert dropped["Status"]["State"] == "SUCCEEDED", dropped["Status"]

    code, _message = _error(lambda: athena.get_database(CatalogName="AwsDataCatalog", DatabaseName=db))
    # message varies: it embeds the request id of Athena's internal Glue call, which the
    # caller never sees
    assert code == "MetadataException", code

    names_after_drop = [
        d["Name"] for d in athena.list_databases(CatalogName="AwsDataCatalog")["DatabaseList"]
    ]
    assert db not in names_after_drop, f"dropped database {db!r} still listed: {names_after_drop!r}"

    qid3 = athena.start_query_execution(
        QueryString=f"DROP DATABASE {db}", ResultConfiguration={"OutputLocation": out}
    )["QueryExecutionId"]
    redropped = _wait_for_query(ctx, qid3)
    assert redropped["Status"]["State"] == "FAILED", (
        f"dropping the already-dropped database {db!r} a second time must fail, "
        f"got {redropped['Status']}"
    )
    assert redropped["Status"]["StateChangeReason"] == (
        f"FAILED: SemanticException [Error 10072]: Database does not exist: {db}"
    ), redropped["Status"]
    assert redropped["Status"]["AthenaError"]["ErrorMessage"] == (
        f"Cannot drop database {db}, as it does not exist."
    ), redropped["Status"]


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises, so a
    target that accepts what real AWS refuses never reads as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _make_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-out-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        # us-east-1 is S3's API-level default region; CreateBucketConfiguration must be
        # omitted there or the call is rejected with InvalidLocationConstraint.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "database-ddl-lifecycle"},
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
