"""bytes-scanned-cutoff-fails-the-oversized-query."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bytes-scanned-cutoff-fails-the-oversized-query"
GROUP = 'workgroup'
SERVICES = ['athena']


#: Athena's smallest accepted BytesScannedCutoffPerQuery: botocore rejects 1048576 with
#: `valid min value: 10000000`, so the cutoff is 10 MILLION bytes (decimal), not 10 MiB.
_CUTOFF_BYTES = 10000000


def _empty_and_delete_bucket(s3, bucket):
    """Delete EVERY object before DeleteBucket.

    Athena writes its own result artifacts into the output location, and this check additionally
    uploads ~14 MB of scan fodder, so a bucket that only ever received our uploads is still
    non-empty at teardown. DeleteBucket on a non-empty bucket fails, and a failed DeleteBucket is
    the single most likely cost leak in this service — hence the paginated delete_objects sweep.
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
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "bytes-scanned-cutoff"},
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
    """GetQueryResults rows for a SELECT: row 0 repeats the column names, so the data rows are
    rows[1:]."""
    rows = results["ResultSet"]["Rows"]
    return [[d.get("VarCharValue") for d in r["Data"]] for r in rows[1:]]


def _error(fn):
    """The botocore (Error.Code, Error.Message) raised by fn(), or a hard failure if the call
    unexpectedly SUCCEEDS: accepting input real AWS rejects is a failure in its own right."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to raise a ClientError but SUCCEEDED")


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
    """A workgroup's BytesScannedCutoffPerQuery aborts an oversized scan mid-flight: it ends
    CANCELLED with 'Bytes scanned limit was exceeded', DataScannedInBytes equal to the cutoff and no
    result set, while an under-cutoff query in the same workgroup SUCCEEDS with its row."""
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    out = _output_location(ctx)
    data_bucket = _make_bucket(ctx, "sim2real-behav-athena-data-")

    # ~14 MB, comfortably over the cutoff, in three objects so the engine has real splits to
    # abandon. Uploading it takes well under a second (measured: 0.4 s).
    chunk = "".join(f"{i},{'x' * 40}\n" for i in range(100000)).encode()
    assert len(chunk) * 3 > _CUTOFF_BYTES, (
        f"the oversized table must exceed the cutoff: {len(chunk) * 3!r} vs {_CUTOFF_BYTES!r}")
    for i in range(3):
        s3.put_object(Bucket=data_bucket, Key=f"big/part{i}.csv", Body=chunk)

    marker = ctx.unique_name("").replace("-", "")[:12]
    small_body = f"1,alpha-{marker}\n".encode()
    s3.put_object(Bucket=data_bucket, Key="small/rows.csv", Body=small_body)

    database = ctx.unique_name("sim2real-behav-db-").replace("-", "_")
    big = ctx.unique_name("sim2real-behav-big-").replace("-", "_")
    small = ctx.unique_name("sim2real-behav-small-").replace("-", "_")
    ctx.on_cleanup(lambda: _run_sql(athena, out, f"DROP DATABASE IF EXISTS `{database}` CASCADE"))
    _run_sql(athena, out, f"CREATE DATABASE `{database}`")
    _run_sql(athena, out,
             f"CREATE EXTERNAL TABLE `{database}`.`{big}` (`id` int, `pad` string) "
             "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE "
             f"LOCATION 's3://{data_bucket}/big/'")
    _run_sql(athena, out,
             f"CREATE EXTERNAL TABLE `{database}`.`{small}` (`id` int, `name` string) "
             "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE "
             f"LOCATION 's3://{data_bucket}/small/'")

    # The one thing that is broken: this workgroup caps the scan. EnforceWorkGroupConfiguration
    # is what stops a client-supplied ResultConfiguration from routing around the cap.
    wg = ctx.unique_name("sim2real-behav-athena-wg-")
    athena.create_work_group(
        Name=wg,
        Configuration={
            "ResultConfiguration": {"OutputLocation": out},
            "EnforceWorkGroupConfiguration": True,
            "BytesScannedCutoffPerQuery": _CUTOFF_BYTES,
        },
        Tags=[{"Key": "sim2real", "Value": "bytes-scanned-cutoff"}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))
    echoed = athena.get_work_group(WorkGroup=wg)["WorkGroup"]["Configuration"][
        "BytesScannedCutoffPerQuery"]
    assert echoed == _CUTOFF_BYTES, (
        f"the workgroup must hold the cutoff we configured, got {echoed!r}")

    # --- the refusal: an oversized scan is aborted, and stops AT the limit ---
    big_qid = _start_query(athena, None, f"SELECT count(*) FROM {_dml_name(database, big)}",
                           database=database, workgroup=wg)
    big_state = _wait_terminal(athena, big_qid)
    big_exec = athena.get_query_execution(QueryExecutionId=big_qid)["QueryExecution"]
    big_reason = big_exec["Status"].get("StateChangeReason")
    big_bytes = big_exec["Statistics"]["DataScannedInBytes"]
    assert big_state == "CANCELLED", (
        f"a scan over {len(chunk) * 3} bytes in a workgroup capped at {_CUTOFF_BYTES} must be "
        f"aborted as CANCELLED, got {big_state!r} after scanning {big_bytes!r} bytes "
        f"(reason {big_reason!r})")
    assert big_reason == "Bytes scanned limit was exceeded", (
        f"the abort must name the cutoff as its cause, got StateChangeReason {big_reason!r}")
    assert big_bytes == _CUTOFF_BYTES, (
        f"the engine must stop AT the cutoff rather than reading the whole "
        f"{len(chunk) * 3}-byte table: DataScannedInBytes must be exactly {_CUTOFF_BYTES}, got "
        f"{big_bytes!r}")

    # --- the effect is absent: there is no result set to fetch ---
    code, message = _error(lambda: athena.get_query_results(QueryExecutionId=big_qid))
    assert code == "InvalidRequestException", (
        f"an aborted query has no results, so GetQueryResults must be refused with "
        f"InvalidRequestException; got {code!r}")
    assert message == "Could not find results", repr(message)

    # --- the positive control, in the SAME enforcing workgroup: under the cutoff still works ---
    small_qid = _start_query(athena, None,
                             f"SELECT name FROM {_dml_name(database, small)} ORDER BY name",
                             database=database, workgroup=wg)
    small_state = _wait_terminal(athena, small_qid)
    small_exec = athena.get_query_execution(QueryExecutionId=small_qid)["QueryExecution"]
    assert small_state == "SUCCEEDED", (
        f"the under-cutoff control query must succeed in the same workgroup, proving the cutoff is "
        f"size-dependent and not a blanket refusal; got {small_state!r} / "
        f"{small_exec['Status'].get('StateChangeReason')!r}")
    small_rows = _data_rows(athena.get_query_results(QueryExecutionId=small_qid))
    assert small_rows == [[f"alpha-{marker}"]], (
        f"the control query must return this run's row (marker {marker!r}), got {small_rows!r}")
    small_bytes = small_exec["Statistics"]["DataScannedInBytes"]
    assert small_bytes == len(small_body), (
        f"the control query must read exactly the {len(small_body)} bytes it was given and be "
        f"nowhere near the cutoff, got DataScannedInBytes={small_bytes!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
