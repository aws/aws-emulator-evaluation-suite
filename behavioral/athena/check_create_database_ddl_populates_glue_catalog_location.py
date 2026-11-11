"""create-database-ddl-populates-glue-catalog-location."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-database-ddl-populates-glue-catalog-location"
GROUP = "state-machine"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CREATE DATABASE ... LOCATION query sets the Glue database's LocationUri, read from Glue
    directly; the DDL returns no rows or columns and still carries a ResultConfiguration.
    """
    bucket = _make_output_bucket(ctx)
    athena = ctx.client("athena")
    glue = ctx.client("glue")
    out = f"s3://{bucket}/out/"
    db = ctx.unique_name("sim2real_athena_gluedb_").replace("-", "_")
    location = f"s3://{bucket}/db/"

    qid = athena.start_query_execution(
        QueryString=f"CREATE DATABASE {db} LOCATION '{location}'",
        ResultConfiguration={"OutputLocation": out},
    )["QueryExecutionId"]
    created = _wait_for_query(ctx, qid)
    assert created["Status"]["State"] == "SUCCEEDED", created["Status"]
    assert created["StatementType"] == "DDL", created["StatementType"]
    ctx.on_cleanup(lambda: _wait_for_query(
        ctx,
        athena.start_query_execution(
            QueryString=f"DROP DATABASE {db}", ResultConfiguration={"OutputLocation": out}
        )["QueryExecutionId"],
    ))

    # ResultConfiguration is populated even for a DDL execution (an output .txt object is written).
    result_config = created.get("ResultConfiguration")
    assert result_config is not None, (
        f"expected GetQueryExecution to carry a ResultConfiguration even for DDL, got {created!r}"
    )
    assert result_config["OutputLocation"].startswith(out), (
        f"expected the DDL's OutputLocation to live under {out!r}, got {result_config['OutputLocation']!r}"
    )

    results = athena.get_query_results(QueryExecutionId=qid)["ResultSet"]
    assert results["Rows"] == [], f"expected no result rows for a DDL execution, got {results['Rows']!r}"
    assert results["ResultSetMetadata"]["ColumnInfo"] == [], (
        f"expected no column metadata for a DDL execution, got {results['ResultSetMetadata']['ColumnInfo']!r}"
    )

    glue_db = glue.get_database(Name=db)["Database"]
    assert glue_db["Name"] == db, f"expected Glue database name {db!r}, got {glue_db['Name']!r}"
    assert glue_db["LocationUri"] == location, (
        f"expected Athena's CREATE DATABASE LOCATION to set Glue's LocationUri to {location!r}, "
        f"got {glue_db.get('LocationUri')!r}"
    )


def _make_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-out-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "create-database-ddl-populates-glue-catalog-location"},
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
