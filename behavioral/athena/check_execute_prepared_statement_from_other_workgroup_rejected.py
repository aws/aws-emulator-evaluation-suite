"""execute-prepared-statement-from-other-workgroup-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-prepared-statement-from-other-workgroup-rejected"
GROUP = 'prepared-statement'
SERVICES = ['athena']




def _empty_and_delete_bucket(s3, bucket):
    """Delete every object, including Athena's own result artifacts, then the bucket."""
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
        {"Key": "sim2real", "Value": "execute-prepared-statement-from-other-workgroup"},
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


def _list_prepared_statements(athena, workgroup):
    """Every statement name in a workgroup, across all pages.

    botocore ships no paginator for list_prepared_statements, so NextToken is followed by hand.
    """
    names, token = [], None
    while True:
        kwargs = {"WorkGroup": workgroup, "MaxResults": 50}
        if token:
            kwargs["NextToken"] = token
        page = athena.list_prepared_statements(**kwargs)
        names.extend(s["StatementName"] for s in page.get("PreparedStatements", []))
        token = page.get("NextToken")
        if not token:
            return sorted(names)


def _error(fn):
    """The botocore (Error.Code, Error.Message) raised by fn(); fails if the call succeeds."""
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
    """EXECUTE of a prepared statement from a non-owning workgroup fails synchronously with
    InvalidRequestException and the statement is invisible there; the owning workgroup returns the row.
    """
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    out = _output_location(ctx)
    data_bucket = _make_bucket(ctx, "sim2real-behav-athena-data-")

    marker = ctx.unique_name("").replace("-", "")[:12]
    s3.put_object(Bucket=data_bucket, Key="src/rows.csv",
                  Body=f"1,alpha-{marker}\n2,bravo-{marker}\n3,charlie-{marker}\n".encode())

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

    # Two workgroups identical except which one owns the statement.
    wg_owner = ctx.unique_name("sim2real-behav-athena-wg-")
    wg_other = ctx.unique_name("sim2real-behav-athena-wg-")
    for name in (wg_owner, wg_other):
        athena.create_work_group(
            Name=name,
            Configuration={"ResultConfiguration": {"OutputLocation": out},
                           "EnforceWorkGroupConfiguration": True},
            Tags=[{"Key": "sim2real", "Value": "execute-prepared-statement-scope"}],
        )
        ctx.on_cleanup(
            lambda n=name: athena.delete_work_group(WorkGroup=n, RecursiveDeleteOption=True))

    stmt = ctx.unique_name("sim2real_ps_").replace("-", "_")
    athena.create_prepared_statement(
        StatementName=stmt,
        WorkGroup=wg_owner,
        QueryStatement=f"SELECT name FROM {_dml_name(database, table)} WHERE id = ?",
    )
    # Explicit, not reliant on the workgroup's RecursiveDeleteOption.
    ctx.on_cleanup(
        lambda: athena.delete_prepared_statement(StatementName=stmt, WorkGroup=wg_owner))

    # --- the refusal: the same EXECUTE, submitted to the workgroup that does not own it ---
    code, message = _error(lambda: athena.start_query_execution(
        QueryString=f"EXECUTE {stmt} USING 2",
        WorkGroup=wg_other,
        QueryExecutionContext={"Database": database},
    ))
    assert code == "InvalidRequestException", (
        f"EXECUTE-ing prepared statement {stmt!r} from workgroup {wg_other!r}, which does not own "
        f"it, must be refused with InvalidRequestException; got {code!r}")
    assert message == "PreparedStatement was not found in workGroup", repr(message)

    # --- the effect is absent: the statement is not visible in the other workgroup at all ---
    other_names = _list_prepared_statements(athena, wg_other)
    assert stmt not in other_names, (
        f"the statement must not be visible in the non-owning workgroup; "
        f"ListPreparedStatements({wg_other!r}) returned {other_names!r}")
    get_code, get_message = _error(
        lambda: athena.get_prepared_statement(StatementName=stmt, WorkGroup=wg_other))
    assert get_code == "ResourceNotFoundException", (
        f"GetPreparedStatement in the non-owning workgroup must report the statement as absent; "
        f"got {get_code!r}")
    assert get_message == (
        f"No Prepared Statement with statement name {stmt} exists in WorkGroup {wg_other}"
    ), repr(get_message)

    # --- it is still there in the owning workgroup: the refusal was about scope, not deletion ---
    owner_names = _list_prepared_statements(athena, wg_owner)
    assert stmt in owner_names, (
        f"the statement must still be listed by its owning workgroup {wg_owner!r}; "
        f"ListPreparedStatements returned {owner_names!r}")

    # --- the positive control: the identical EXECUTE in the owning workgroup binds and returns ---
    control_qid = _start_query(athena, None, f"EXECUTE {stmt} USING 2",
                               database=database, workgroup=wg_owner)
    control_state = _wait_terminal(athena, control_qid)
    control_exec = athena.get_query_execution(QueryExecutionId=control_qid)["QueryExecution"]
    assert control_state == "SUCCEEDED", (
        f"the identical EXECUTE must succeed in the owning workgroup, proving the refusal above "
        f"was the workgroup scope and not a broken statement; got {control_state!r} / "
        f"{control_exec['Status'].get('StateChangeReason')!r}")
    control_rows = _data_rows(athena.get_query_results(QueryExecutionId=control_qid))
    assert control_rows == [[f"bravo-{marker}"]], (
        f"the bound parameter 2 must select exactly the id=2 row (marker {marker!r}); the EXECUTE "
        f"returned {control_rows!r}")
    control_bytes = control_exec["Statistics"]["DataScannedInBytes"]
    assert control_bytes > 0, (
        f"the control EXECUTE must really scan the S3 object, got "
        f"DataScannedInBytes={control_bytes!r} — a fabricated ResultSet scans nothing")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
