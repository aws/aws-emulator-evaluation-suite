"""expected-bucket-owner-mismatch-fails-the-query-and-writes-nothing."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "expected-bucket-owner-mismatch-fails-the-query-and-writes-nothing"
GROUP = "error-semantics"
SERVICES = ["athena"]


def _empty_and_delete_bucket(s3, bucket):
    """Delete every object, then the bucket; Athena writes its own result objects into it."""
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
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
        {"Key": "sim2real", "Value": CHECK},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})
    return bucket


def _start_query(athena, result_config, query_string, workgroup=None, database=None):
    kwargs = {"QueryString": query_string}
    if result_config:
        kwargs["ResultConfiguration"] = result_config
    if workgroup:
        kwargs["WorkGroup"] = workgroup
    if database:
        kwargs["QueryExecutionContext"] = {"Database": database}
    return athena.start_query_execution(**kwargs)["QueryExecutionId"]


def _wait_terminal(athena, qid, timeout_s=300, interval_s=2):
    """Poll GetQueryExecution to a terminal state within a bounded deadline; raise on timeout."""
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


def _run_sql(athena, result_config, sql, database=None, workgroup=None):
    qid = _start_query(athena, result_config, sql, database=database, workgroup=workgroup)
    state = _wait_terminal(athena, qid)
    if state != "SUCCEEDED":
        status = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
        raise AssertionError(
            f"statement reached {state}, expected SUCCEEDED: {sql!r} -- "
            f"{status.get('StateChangeReason')}")
    return qid


def _data_rows(results):
    """Data rows of a SELECT ResultSet; row 0 repeats the column names."""
    rows = results["ResultSet"]["Rows"]
    return [[d.get("VarCharValue") for d in r["Data"]] for r in rows[1:]]


def _dml_name(database, table):
    """DML goes through the Trino parser (double-quoted identifiers); DDL through Hive
    (backticks). A backtick inside a SELECT is refused synchronously by StartQueryExecution."""
    return f'"{database}"."{table}"'


def _error(fn):
    """Return the (Error.Code, Error.Message) raised by fn(); raise if fn() succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to raise a ClientError but SUCCEEDED")


def _keys_under(s3, bucket, prefix):
    """Every key under `prefix`."""
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return keys


def _other_account_id(account_id):
    """A documentation placeholder account id that is not the caller's: never a real account."""
    return "111122223333" if account_id != "111122223333" else "444455556666"


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A mismatched ResultConfiguration.ExpectedBucketOwner fails the query and writes nothing under
    the output prefix, while the identical query with this account as owner succeeds.

    Reference: https://docs.aws.amazon.com/athena/latest/APIReference/API_ResultConfiguration.html
    """
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    wrong_owner = _other_account_id(account_id)

    results_bucket = _make_bucket(ctx, "sim2real-behav-athena-results-")
    prefix = "results/"
    out = f"s3://{results_bucket}/{prefix}"
    data_bucket = _make_bucket(ctx, "sim2real-behav-athena-data-")
    marker = ctx.unique_name("").replace("-", "")[:12]
    body = f"1,owner-{marker}\n".encode()
    s3.put_object(Bucket=data_bucket, Key="rows/data.csv", Body=body)

    # ExpectedBucketOwner is a CLIENT-side ResultConfiguration setting, so the workgroup must not
    # override client settings or the field under test would never be consulted.
    wg = ctx.unique_name("sim2real-behav-athena-wg-ebo-")
    athena.create_work_group(
        Name=wg,
        Configuration={"EnforceWorkGroupConfiguration": False},
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))
    enforced = athena.get_work_group(WorkGroup=wg)["WorkGroup"]["Configuration"][
        "EnforceWorkGroupConfiguration"]
    assert enforced is False, (
        f"the client's ResultConfiguration must be the one in force for this check to be about "
        f"ExpectedBucketOwner at all; GetWorkGroup reported "
        f"EnforceWorkGroupConfiguration={enforced!r}")

    good_config = {"OutputLocation": out, "ExpectedBucketOwner": account_id}
    bad_config = {"OutputLocation": out, "ExpectedBucketOwner": wrong_owner}

    database = ctx.unique_name("sim2real-behav-db-").replace("-", "_")
    table = ctx.unique_name("sim2real-behav-tbl-").replace("-", "_")
    ctx.on_cleanup(
        lambda: _run_sql(athena, good_config, f"DROP DATABASE IF EXISTS `{database}` CASCADE"))
    _run_sql(athena, good_config, f"CREATE DATABASE `{database}`")
    _run_sql(
        athena, good_config,
        f"CREATE EXTERNAL TABLE `{database}`.`{table}` (`id` int, `name` string) "
        "ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' STORED AS TEXTFILE "
        f"LOCATION 's3://{data_bucket}/rows/'")

    sql = f"SELECT name FROM {_dml_name(database, table)} ORDER BY name"

    ok_qid = _start_query(athena, good_config, sql, workgroup=wg, database=database)
    ok_state = _wait_terminal(athena, ok_qid)
    ok_reason = athena.get_query_execution(QueryExecutionId=ok_qid)["QueryExecution"][
        "Status"].get("StateChangeReason")
    assert ok_state == "SUCCEEDED", (
        f"with ExpectedBucketOwner set to this account ({account_id}) the query must succeed, "
        f"proving the wiring is otherwise healthy; got {ok_state!r} / {ok_reason!r}")
    ok_rows = _data_rows(athena.get_query_results(QueryExecutionId=ok_qid))
    assert ok_rows == [[f"owner-{marker}"]], (
        f"the control query must return this run's own row (marker {marker!r}), got {ok_rows!r}")
    ok_keys = _keys_under(s3, results_bucket, prefix)
    assert f"{prefix}{ok_qid}.csv" in ok_keys, (
        f"the control query's result object must exist at {prefix}{ok_qid}.csv, so the failed "
        f"leg's absence means something; the prefix held {ok_keys!r}")

    # Athena accepts the query and enforces the owner guard asynchronously at write time.
    bad_qid = _start_query(athena, bad_config, sql, workgroup=wg, database=database)
    bad_state = _wait_terminal(athena, bad_qid)
    bad_exec = athena.get_query_execution(QueryExecutionId=bad_qid)["QueryExecution"]
    bad_reason = bad_exec["Status"].get("StateChangeReason") or ""
    assert bad_state == "FAILED", (
        f"with ExpectedBucketOwner={wrong_owner} (which does not own {results_bucket}) the "
        f"identical query must reach FAILED, got {bad_state!r} (reason {bad_reason!r})")
    expected_reason = (
        f"Access denied when writing output to url: {out}{bad_qid}.csv . Please ensure you are "
        f"allowed to access the S3 bucket. If specifying an expected bucket owner, confirm the "
        f"bucket is owned by the expected account. If you are encrypting query results with KMS "
        f"key, please ensure you are allowed to access your KMS key")
    assert bad_reason == expected_reason, (
        f"the failure must name the denied S3 write as its cause with AWS's exact "
        f"StateChangeReason {expected_reason!r}, got {bad_reason!r}")
    athena_error = bad_exec["Status"]["AthenaError"]
    assert athena_error["ErrorCategory"] == 2, (
        f"a caller-supplied owner mismatch is a USER error, so AthenaError.ErrorCategory must be "
        f"2 per the Smithy doc (1=System, 2=User, 3=Other); got {athena_error!r}")

    after_keys = _keys_under(s3, results_bucket, prefix)
    leaked = [k for k in after_keys if bad_qid in k]
    assert leaked == [], (
        f"a query refused by the ExpectedBucketOwner guard must write NOTHING for its execution "
        f"id, yet {leaked!r} appeared under s3://{results_bucket}/{prefix}")
    code, message = _error(lambda: athena.get_query_results(QueryExecutionId=bad_qid))
    assert code == "InvalidRequestException", (
        f"a FAILED query has no results, so GetQueryResults must be refused with "
        f"InvalidRequestException, got {code!r}")
    expected_message = "Query did not finish successfully. Final query state: FAILED"
    assert message == expected_message, (
        f"the refusal must carry AWS's exact message {expected_message!r}, got {message!r} "
        f"(StateChangeReason {bad_reason!r})")

    restored_qid = _start_query(athena, good_config, sql, workgroup=wg, database=database)
    restored_state = _wait_terminal(athena, restored_qid)
    restored_reason = athena.get_query_execution(QueryExecutionId=restored_qid)["QueryExecution"][
        "Status"].get("StateChangeReason")
    assert restored_state == "SUCCEEDED", (
        f"with the correct owner id restored the identical query must succeed again, proving the "
        f"failure was the owner guard and not a poisoned table or bucket; got "
        f"{restored_state!r} / {restored_reason!r}")
    restored_keys = _keys_under(s3, results_bucket, prefix)
    assert f"{prefix}{restored_qid}.csv" in restored_keys, (
        f"the restored query's result object must land at {prefix}{restored_qid}.csv; the prefix "
        f"held {restored_keys!r}")
    restored_rows = _data_rows(athena.get_query_results(QueryExecutionId=restored_qid))
    assert restored_rows == ok_rows, (
        f"the restored query must return the same row as the control ({ok_rows!r}), got "
        f"{restored_rows!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
