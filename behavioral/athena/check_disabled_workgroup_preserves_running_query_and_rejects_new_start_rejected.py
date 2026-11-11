"""disabled-workgroup-preserves-running-query-and-rejects-new-start-rejected."""
from __future__ import annotations

import collections
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disabled-workgroup-preserves-running-query-and-rejects-new-start-rejected"
GROUP = 'workgroup'
SERVICES = ['athena']


#: Self-join moduli over the 300 000-row table: 97 keeps a query RUNNING for ~15 s; 29 and 11 are
#: heavier rungs used only if a lighter one finishes before the workgroup can be disabled.
_JOIN_MODULI = (97, 29, 11)

_ROWS_PER_FILE = 100000
_FILE_COPIES = 3


def _empty_and_delete_bucket(s3, bucket):
    """Delete every object, including Athena's own result artifacts, then DeleteBucket."""
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
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "disabled-workgroup-preserves-running-query"},
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
    """GetQueryResults data rows for a SELECT: row 0 repeats the column names."""
    rows = results["ResultSet"]["Rows"]
    return [[d.get("VarCharValue") for d in r["Data"]] for r in rows[1:]]


def _error(fn):
    """The botocore (Error.Code, Error.Message) raised by fn(); an unexpected success fails."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to raise a ClientError but SUCCEEDED")


def _expected_self_join_pairs(modulus):
    """How many rows `t JOIN t ON a.id %% m = b.id %% m` must produce over the uploaded table.

    Each residue r emits (copies * count_r)^2 pairs.
    """
    counts = collections.Counter(i % modulus for i in range(_ROWS_PER_FILE))
    return sum((_FILE_COPIES * n) ** 2 for n in counts.values())


def _dml_name(database, table):
    """Athena parses DDL with the Hive parser (BACKTICK identifiers) and DML with the Trino parser
    (DOUBLE-QUOTE identifiers)."""
    return f'"{database}"."{table}"'


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c2",
    "cap:c3",
)
def run(ctx) -> None:
    """Disabling a workgroup refuses a new StartQueryExecution with InvalidRequestException, while
    a query already RUNNING still SUCCEEDS with its correct result; re-enabling restores admission.
    """
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    out = _output_location(ctx)
    data_bucket = _make_bucket(ctx, "sim2real-behav-athena-data-")

    # ~14 MB / 300 000 rows: enough for a self-join that stays RUNNING for seconds.
    chunk = "".join(f"{i},{'x' * 40}\n" for i in range(_ROWS_PER_FILE)).encode()
    for i in range(_FILE_COPIES):
        s3.put_object(Bucket=data_bucket, Key=f"big/part{i}.csv", Body=chunk)

    marker = ctx.unique_name("").replace("-", "")[:12]
    s3.put_object(Bucket=data_bucket, Key="tiny/rows.csv", Body=f"1,alpha-{marker}\n".encode())

    database = ctx.unique_name("sim2real-behav-db-").replace("-", "_")
    big = ctx.unique_name("sim2real-behav-big-").replace("-", "_")
    tiny = ctx.unique_name("sim2real-behav-tiny-").replace("-", "_")
    ctx.on_cleanup(lambda: _run_sql(athena, out, f"DROP DATABASE IF EXISTS `{database}` CASCADE"))
    _run_sql(athena, out, f"CREATE DATABASE `{database}`")
    _run_sql(athena, out,
             f"CREATE EXTERNAL TABLE `{database}`.`{big}` (`id` int, `pad` string) "
             "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE "
             f"LOCATION 's3://{data_bucket}/big/'")
    _run_sql(athena, out,
             f"CREATE EXTERNAL TABLE `{database}`.`{tiny}` (`id` int, `name` string) "
             "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE "
             f"LOCATION 's3://{data_bucket}/tiny/'")

    wg = ctx.unique_name("sim2real-behav-athena-wg-")
    athena.create_work_group(
        Name=wg,
        Configuration={"ResultConfiguration": {"OutputLocation": out},
                       "EnforceWorkGroupConfiguration": True},
        Tags=[{"Key": "sim2real", "Value": "disabled-workgroup-interleave"}],
    )
    # Re-enable first so a leftover is still usable if the delete ever fails.
    def _teardown_wg():
        try:
            athena.update_work_group(WorkGroup=wg, State="ENABLED")
        except ClientError as exc:
            # Only an unknown workgroup ("WorkGroup is not found.") means nothing is left.
            if "not found" in exc.response["Error"].get("Message", ""):
                return
            raise
        athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True)

    ctx.on_cleanup(_teardown_wg)

    tiny_sql = f"SELECT name FROM {_dml_name(database, tiny)} ORDER BY name"

    # The interleave window comes from data volume, never from a sleep.
    inflight_qid = None
    modulus = None
    for candidate in _JOIN_MODULI:
        qid = _start_query(
            athena, None,
            f"SELECT count(*) FROM {_dml_name(database, big)} a "
            f"JOIN {_dml_name(database, big)} b ON a.id % {candidate} = b.id % {candidate}",
            database=database, workgroup=wg)
        deadline = time.monotonic() + 120
        state = None
        while time.monotonic() < deadline:
            state = athena.get_query_execution(QueryExecutionId=qid)[
                "QueryExecution"]["Status"]["State"]
            if state in ("RUNNING", "SUCCEEDED", "FAILED", "CANCELLED"):
                break
            time.sleep(0.3)
        assert state in ("RUNNING", "SUCCEEDED"), (
            f"the self-join over {_FILE_COPIES * _ROWS_PER_FILE} rows (mod {candidate}) ended "
            f"{state!r} instead of running or succeeding")
        if state != "RUNNING":
            # Finished before it could be interleaved with: escalate to a heavier join.
            continue

        athena.update_work_group(WorkGroup=wg, State="DISABLED")
        after = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
        if after == "RUNNING":
            inflight_qid, modulus = qid, candidate
            break
        assert after == "SUCCEEDED", (
            f"disabling the workgroup must not kill a query it had already admitted; the RUNNING "
            f"self-join (mod {candidate}) read {after!r} right after the disable")
        # Finished before the disable landed: re-enable and escalate to a heavier join.
        athena.update_work_group(WorkGroup=wg, State="ENABLED")
    if inflight_qid is None:
        raise TimeoutError(
            f"no self-join rung {_JOIN_MODULI} stayed RUNNING across the disable; the preserved "
            "in-flight query is not graded")

    code, message = _error(lambda: athena.start_query_execution(
        QueryString=tiny_sql, WorkGroup=wg,
        QueryExecutionContext={"Database": database}))
    assert code == "InvalidRequestException", (
        f"StartQueryExecution in a DISABLED workgroup must be refused with "
        f"InvalidRequestException; got {code!r}")
    expected = f"WorkGroup {wg} is disabled."
    assert message == expected, (
        f"the refusal must carry AWS's exact message {expected!r}; got {message!r}")

    inflight_state = _wait_terminal(athena, inflight_qid)
    inflight_exec = athena.get_query_execution(QueryExecutionId=inflight_qid)["QueryExecution"]
    assert inflight_state == "SUCCEEDED", (
        f"disabling the workgroup must not kill a query it had already admitted; the in-flight "
        f"self-join reached {inflight_state!r} / "
        f"{inflight_exec['Status'].get('StateChangeReason')!r}")
    expected = _expected_self_join_pairs(modulus)
    inflight_rows = _data_rows(athena.get_query_results(QueryExecutionId=inflight_qid))
    assert inflight_rows == [[str(expected)]], (
        f"the in-flight self-join (mod {modulus}) must return its full, correct count of "
        f"{expected} matched pairs over the {_FILE_COPIES * _ROWS_PER_FILE} uploaded rows; it "
        f"returned {inflight_rows!r}")
    inflight_bytes = inflight_exec["Statistics"]["DataScannedInBytes"]
    # A self-join reads the table on both sides, so the accounting is twice the table size.
    assert inflight_bytes == 2 * len(chunk) * _FILE_COPIES, (
        f"the in-flight self-join must have read every byte of the table on BOTH sides of the "
        f"join: expected {2 * len(chunk) * _FILE_COPIES}, got "
        f"DataScannedInBytes={inflight_bytes!r}")

    # Positive control: re-enabling restores admission for the identical query.
    athena.update_work_group(WorkGroup=wg, State="ENABLED")
    control_qid = _start_query(athena, None, tiny_sql, database=database, workgroup=wg)
    control_state = _wait_terminal(athena, control_qid)
    assert control_state == "SUCCEEDED", (
        f"the identical query refused a moment ago must succeed once the workgroup is ENABLED "
        f"again, proving the refusal was the DISABLED state and not a broken workgroup; got "
        f"{control_state!r}")
    control_rows = _data_rows(athena.get_query_results(QueryExecutionId=control_qid))
    assert control_rows == [[f"alpha-{marker}"]], (
        f"the re-admitted query must return this run's row (marker {marker!r}), got "
        f"{control_rows!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
