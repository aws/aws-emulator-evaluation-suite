"""concurrent-identical-queries-result-reuse-invariant."""
from __future__ import annotations

import concurrent.futures
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-identical-queries-result-reuse-invariant"
GROUP = 'concurrency'
SERVICES = ['athena']


_N_CONCURRENT = 8

#: The DML concurrency quota is per account and shared with anything else running in the
#: account, so a ThrottlingException here is an environment condition, not a failed
#: execution. Retried with a bounded backoff (a bounded retry loop, which is the idiomatic wait).
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException")


def _empty_and_delete_bucket(s3, bucket):
    """Delete EVERY object before DeleteBucket.

    Athena writes its own result artifacts (`<qid>.csv`, `<qid>.csv.metadata`) into the output
    location — nine of them here, one per execution — so a bucket that only ever received our
    uploads is still non-empty at teardown. DeleteBucket on a non-empty bucket fails, and a failed
    DeleteBucket is the single most likely cost leak in this service — hence the paginated
    delete_objects sweep.
    """
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket)


def _make_bucket(ctx, prefix):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix)
    kwargs = {"Bucket": bucket}
    # us-east-1 is CreateBucket's default region and rejects an explicit LocationConstraint
    # for itself; every other region requires one. Not a region assumption about ctx.region.
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "concurrent-identical-queries-result-reuse"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})
    return bucket


def _output_location(ctx):
    return f"s3://{_make_bucket(ctx, 'sim2real-behav-athena-results-')}/results/"


def _start_query(athena, out, query_string, workgroup=None, database=None, **extra):
    kwargs = {"QueryString": query_string}
    if out:
        kwargs["ResultConfiguration"] = {"OutputLocation": out}
    if workgroup:
        kwargs["WorkGroup"] = workgroup
    if database:
        kwargs["QueryExecutionContext"] = {"Database": database}
    kwargs.update(extra)
    return athena.start_query_execution(**kwargs)["QueryExecutionId"]


def _start_with_throttle_retry(athena, sql, database, workgroup, reuse):
    """StartQueryExecution with a bounded backoff over the throttle codes only.

    A ThrottlingException must be retried, not counted as a failed execution: the per-account DML
    concurrency quota is shared with every other workload running in the same account. Any
    OTHER ClientError is re-raised immediately — swallowing it would turn a real fidelity failure
    into a timeout.
    """
    last = None
    for attempt in range(6):
        try:
            return _start_query(athena, None, sql, database=database, workgroup=workgroup,
                                ResultReuseConfiguration=reuse)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _THROTTLE_CODES:
                raise
            last = code
            time.sleep(2 * (attempt + 1))
    raise AssertionError(f"StartQueryExecution stayed throttled ({last!r}) across 6 attempts")


def _wait_terminal(athena, qid, timeout_s=300, interval_s=2):
    """Poll GetQueryExecution to a REQUIRED terminal state with a bounded deadline."""
    terminal = ("SUCCEEDED", "FAILED", "CANCELLED")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
        if state in terminal:
            return state
        time.sleep(interval_s)
    raise AssertionError(
        f"query {qid} did not reach a terminal state within {timeout_s}s (last={state})")


def _run_sql(athena, out, sql, database=None, workgroup=None, **extra):
    qid = _start_query(athena, out, sql, database=database, workgroup=workgroup, **extra)
    state = _wait_terminal(athena, qid)
    if state != "SUCCEEDED":
        status = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
        raise AssertionError(
            f"statement reached {state}, expected SUCCEEDED: {sql!r} -- "
            f"{status.get('StateChangeReason')}"
        )
    return qid


def _data_rows(results):
    """GetQueryResults rows for a SELECT: row 0 repeats the column names, so the data rows are
    rows[1:]. Returned as a LIST, never a set — ORDER BY makes the order a server-side guarantee
    and an emulator that shuffles must fail."""
    rows = results["ResultSet"]["Rows"]
    return [[d.get("VarCharValue") for d in r["Data"]] for r in rows[1:]]


def _dml_name(database, table):
    """Athena parses DDL with the Hive parser (BACKTICK identifiers) and DML with the Trino parser
    (DOUBLE-QUOTE identifiers)."""
    return f'"{database}"."{table}"'


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c2", "cap:c3")
def run(ctx) -> None:
    """Eight identical concurrent queries with result reuse enabled all SUCCEED with distinct
    QueryExecutionIds and identical rows; an execution that did not reuse scanned exactly the
    table's bytes, and a ninth sequential one that reused scanned exactly zero."""
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    out = _output_location(ctx)
    data_bucket = _make_bucket(ctx, "sim2real-behav-athena-data-")

    # A per-run marker so the eight row sets cannot all agree on a hardcoded fixture.
    marker = ctx.unique_name("").replace("-", "")[:12]
    body = f"1,alpha-{marker}\n2,bravo-{marker}\n3,charlie-{marker}\n".encode()
    s3.put_object(Bucket=data_bucket, Key="src/rows.csv", Body=body)

    database = ctx.unique_name("sim2real-behav-db-").replace("-", "_")
    table = ctx.unique_name("sim2real-behav-tbl-").replace("-", "_")
    ctx.on_cleanup(lambda: _run_sql(athena, out, f"DROP DATABASE IF EXISTS `{database}` CASCADE"))
    _run_sql(athena, out, f"CREATE DATABASE `{database}`")
    _run_sql(
        athena, out,
        f"CREATE EXTERNAL TABLE `{database}`.`{table}` (`id` int, `name` string) "
        "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE "
        f"LOCATION 's3://{data_bucket}/src/'",
    )

    wg = ctx.unique_name("sim2real-behav-athena-wg-")
    athena.create_work_group(
        Name=wg,
        Configuration={"ResultConfiguration": {"OutputLocation": out},
                       "EnforceWorkGroupConfiguration": True},
        Tags=[{"Key": "sim2real", "Value": "concurrent-result-reuse"}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))

    reuse = {"ResultReuseByAgeConfiguration": {"Enabled": True, "MaxAgeInMinutes": 60}}
    sql = f"SELECT id, name FROM {_dml_name(database, table)} ORDER BY id"
    expected_rows = [["1", f"alpha-{marker}"], ["2", f"bravo-{marker}"],
                     ["3", f"charlie-{marker}"]]

    # --- fire all eight at once ---
    with concurrent.futures.ThreadPoolExecutor(max_workers=_N_CONCURRENT) as pool:
        qids = list(pool.map(
            lambda _: _start_with_throttle_retry(athena, sql, database, wg, reuse),
            range(_N_CONCURRENT)))

    assert len(set(qids)) == _N_CONCURRENT, (
        f"{_N_CONCURRENT} simultaneous submissions must be {_N_CONCURRENT} distinct executions "
        f"even when their results are reused; got {len(set(qids))} distinct ids among {qids!r}")

    states, reused_flags, byte_counts, row_sets = [], [], [], []
    for qid in qids:
        states.append(_wait_terminal(athena, qid))
        stats = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Statistics"]
        info = stats.get("ResultReuseInformation")
        assert info is not None, (
            f"execution {qid!r} requested result reuse, so Statistics must carry "
            f"ResultReuseInformation; got {stats!r}")
        reused_flags.append(info["ReusedPreviousResult"])
        byte_counts.append(stats["DataScannedInBytes"])
        row_sets.append(_data_rows(athena.get_query_results(QueryExecutionId=qid)))

    # --- invariant 1: contention does not lose an execution ---
    assert set(states) == {"SUCCEEDED"}, (
        f"every one of {_N_CONCURRENT} identical concurrent executions must succeed; the states "
        f"were {states!r}")

    # --- invariant 2: they all answer the same, correct question ---
    distinct = {tuple(map(tuple, rows)) for rows in row_sets}
    assert len(distinct) == 1, (
        f"identical concurrent queries must return identical rows; {len(distinct)} distinct row "
        f"sets came back: {sorted(distinct)!r}")
    assert row_sets[0] == expected_rows, (
        f"every concurrent execution must return this run's three rows (marker {marker!r}) in "
        f"ORDER BY id order; got {row_sets[0]!r}")

    # --- invariant 3: the flag and the cost agree, per execution, in BOTH directions ---
    for qid, was_reused, scanned in zip(qids, reused_flags, byte_counts):
        if was_reused:
            assert scanned == 0, (
                f"execution {qid!r} reports ReusedPreviousResult=True, so it read a cached result "
                f"and DataScannedInBytes must be exactly 0; got {scanned!r}")
        else:
            assert scanned == len(body), (
                f"execution {qid!r} reports ReusedPreviousResult=False, so it must have scanned "
                f"the whole {len(body)}-byte object itself; got DataScannedInBytes={scanned!r}")
    assert any(b > 0 for b in byte_counts), (
        f"at least one of the {_N_CONCURRENT} executions must really have scanned S3 — if every "
        f"one reports 0 bytes nothing actually ran; byte counts were {byte_counts!r}")

    # --- and the True branch is not vacuous: a ninth, sequential execution MUST reuse ---
    ninth = _start_query(athena, None, sql, database=database, workgroup=wg,
                         ResultReuseConfiguration=reuse)
    assert _wait_terminal(athena, ninth) == "SUCCEEDED", (
        f"the sequential ninth execution of the same query must succeed; {ninth!r} did not")
    ninth_stats = athena.get_query_execution(QueryExecutionId=ninth)["QueryExecution"]["Statistics"]
    ninth_info = ninth_stats.get("ResultReuseInformation")
    assert ninth_info is not None and ninth_info["ReusedPreviousResult"] is True, (
        f"by the time the eight concurrent executions have all SUCCEEDED there is a completed "
        f"result inside MaxAgeInMinutes=60, so a ninth identical query must reuse it; got "
        f"{ninth_info!r}")
    assert ninth_stats["DataScannedInBytes"] == 0, (
        f"the reusing execution scanned nothing, so DataScannedInBytes must be exactly 0; got "
        f"{ninth_stats['DataScannedInBytes']!r}")
    assert _data_rows(athena.get_query_results(QueryExecutionId=ninth)) == expected_rows, (
        f"the reused result must be identical to what the eight fresh executions returned, "
        f"not a different query's cached rows")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
