"""query-execution-result-reuse-ttl-window."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "query-execution-result-reuse-ttl-window"
GROUP = "visibility-timeout-ttl"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartQueryExecution with ResultReuseConfiguration reuses a prior result
    only within its MaxAgeInMinutes TTL window: a MaxAgeInMinutes=0 window treats
    any previous result as already expired and forces a fresh execution."""
    athena = ctx.client("athena")
    bucket = _create_bucket(ctx)
    # Query result reuse is only honored on Athena engine version 3 -- the account's
    # default "primary" workgroup may still be pinned to an older engine version, in
    # which case ResultReuseConfiguration is silently a no-op (ReusedPreviousResult is
    # always False regardless of TTL). Use a dedicated workgroup explicitly pinned to
    # engine version 3 so the reuse behavior under test is actually exercised.
    wg = _create_engine_v3_workgroup(ctx, athena, bucket)
    # A pure constant-literal query with no FROM clause never touches the S3
    # results-cache/eligibility bookkeeping that the real result-reuse feature is built
    # on top of (it has no data source to scan, so there's nothing for Athena to
    # consider "reusing"): on real AWS, ReusedPreviousResult stays False forever for
    # such a query no matter how long you poll. The same is true of the
    # "information_schema.tables" pseudo table: it's metadata about the Data Catalog,
    # not a query against a real, scan-eligible data source, so it never enters the
    # result-reuse cache path either -- ReusedPreviousResult stays False for it too.
    # Use a genuine DML SELECT against a real external table backed by S3 data instead, so
    # the query actually goes through the standard scan/result-cache path that result
    # reuse operates on.
    table = _create_data_table(ctx, athena, bucket, wg)
    query = f"SELECT count(*) AS marker FROM {table}"

    qid1, reused1 = _run_with_reuse(athena, bucket, query, max_age_minutes=60, workgroup=wg)
    assert reused1 is False, f"first execution has nothing to reuse yet, got ReusedPreviousResult={reused1}"

    # Result-reuse eligibility is not always immediately queryable the instant the prior
    # execution reaches SUCCEEDED (a brief propagation lag before the cache lookup finds
    # it); poll by re-issuing the identical execution until it reuses, for up to 150 s.
    qid2, reused2 = _poll_until_reused(
        athena, bucket, query, max_age_minutes=60, workgroup=wg, timeout_s=150, interval_s=8
    )
    assert qid2 != qid1
    assert reused2 is True, (
        f"second identical execution within the 60-minute TTL window should reuse the "
        f"prior result, got ReusedPreviousResult={reused2}"
    )

    qid3, reused3 = _run_with_reuse(athena, bucket, query, max_age_minutes=0, workgroup=wg)
    assert qid3 not in (qid1, qid2)
    assert reused3 is False, (
        f"execution with MaxAgeInMinutes=0 (TTL window immediately elapsed) must run "
        f"fresh, got ReusedPreviousResult={reused3}"
    )


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-athena-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": CHECK},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})

    def _cleanup():
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _poll_until_reused(athena, bucket, query, max_age_minutes, workgroup, timeout_s=200.0, interval_s=8.0):
    deadline = time.monotonic() + timeout_s
    last_qid, last_reused = None, None
    while time.monotonic() < deadline:
        last_qid, last_reused = _run_with_reuse(athena, bucket, query, max_age_minutes, workgroup)
        if last_reused is True:
            return last_qid, last_reused
        time.sleep(interval_s)
    return last_qid, last_reused


def _create_engine_v3_workgroup(ctx, athena, bucket):
    wg = ctx.unique_name("sim2real-behav-reusewg-")
    athena.create_work_group(
        Name=wg,
        Configuration={
            "ResultConfiguration": {"OutputLocation": f"s3://{bucket}/"},
            "EngineVersion": {"SelectedEngineVersion": "Athena engine version 3"},
        },
        Tags=[
            {"Key": "sim2real", "Value": CHECK},
            {"Key": "sim2real:managed", "Value": "true"},
        ],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))
    return wg


def _run_ddl(athena, bucket, workgroup, ddl, timeout_s=30.0):
    resp = athena.start_query_execution(
        QueryString=ddl,
        WorkGroup=workgroup,
        QueryExecutionContext={"Database": "default"},
        ResultConfiguration={"OutputLocation": f"s3://{bucket}/"},
    )
    qid = resp["QueryExecutionId"]
    state = _poll_until(
        lambda: athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"],
        lambda s: s in ("SUCCEEDED", "FAILED", "CANCELLED"),
        timeout_s=timeout_s,
        interval_s=2,
    )
    if state != "SUCCEEDED":
        info = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
        reason = info.get("Status", {}).get("StateChangeReason")
        raise AssertionError(f"DDL {ddl!r} did not succeed, state={state}, reason={reason}")
    return qid


def _create_data_table(ctx, athena, bucket, workgroup):
    """A real external table backed by actual S3 data, so a SELECT against it goes
    through Athena's normal scan/result-cache path -- the path result reuse operates
    on -- unlike a constant-literal query or a Data-Catalog-metadata pseudo table."""
    s3 = ctx.client("s3")
    prefix = "reuse-data/"
    s3.put_object(Bucket=bucket, Key=f"{prefix}sample.csv", Body=b"1,a\n2,b\n3,c\n")
    table = ctx.unique_name("sim2real_behav_reuse_tbl_").lower().replace("-", "_")
    _run_ddl(
        athena,
        bucket,
        workgroup,
        f"CREATE EXTERNAL TABLE {table} (id int, val string) "
        f"ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' "
        f"LOCATION 's3://{bucket}/{prefix}'",
    )
    ctx.on_cleanup(lambda: _run_ddl(athena, bucket, workgroup, f"DROP TABLE IF EXISTS {table}"))
    return table


def _run_with_reuse(athena, bucket, query, max_age_minutes, workgroup):
    resp = athena.start_query_execution(
        QueryString=query,
        WorkGroup=workgroup,
        QueryExecutionContext={"Database": "default"},
        ResultConfiguration={"OutputLocation": f"s3://{bucket}/"},
        ResultReuseConfiguration={
            "ResultReuseByAgeConfiguration": {"Enabled": True, "MaxAgeInMinutes": max_age_minutes}
        },
    )
    qid = resp["QueryExecutionId"]
    # This query (a COUNT(*) over a 3-row external table) completes in a few seconds,
    # so each execution's completion poll is 30 s; the longer window for the async
    # effect under test (result-reuse propagation) belongs to the reuse poll.
    state = _poll_until(
        lambda: athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"],
        lambda s: s in ("SUCCEEDED", "FAILED", "CANCELLED"),
        timeout_s=30,
        interval_s=1,
    )
    assert state == "SUCCEEDED", f"query execution {qid} did not succeed, state={state}"
    exec_info = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
    reused = exec_info.get("Statistics", {}).get("ResultReuseInformation", {}).get("ReusedPreviousResult")
    return qid, reused



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
