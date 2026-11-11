"""get-query-execution-results-and-stop-query-execution-direct-calls."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-query-execution-results-and-stop-query-execution-direct-calls"
GROUP = "task_integrations"
SERVICES = ["athena", "s3", "stepfunctions"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Direct (non-.sync) athena:getQueryExecution and athena:getQueryResults tasks report a
    query Athena already ran, and athena:stopQueryExecution cancels one still running.
    """
    athena = ctx.client("athena")

    bucket = _create_bucket(ctx)
    workgroup = _create_workgroup(ctx, bucket)
    role_arn = _create_sfn_role(ctx, bucket, workgroup)
    sm_arn = _create_state_machine(ctx, workgroup, role_arn)

    marker = ctx.unique_name("sim2real-marker-")
    fast_qid = _run_query_to_completion(ctx, workgroup, f"SELECT '{marker}' AS marker")

    exec_arn, desc = _run_to_terminal(ctx, sm_arn, {"readQueryId": fast_qid, "workgroup": workgroup})
    assert desc["status"] == "SUCCEEDED", (
        f"execution ended {desc['status']!r}: {desc.get('error')!r} {desc.get('cause')!r}"
    )

    output = json.loads(desc["output"])
    started_qid = output["startSlowQuery"]["QueryExecutionId"]
    ctx.on_cleanup(lambda: _best_effort_stop_query(ctx, started_qid))
    read_exec = output["readExecution"]["QueryExecution"]
    assert read_exec["QueryExecutionId"] == fast_qid, (
        f"getQueryExecution reported {read_exec.get('QueryExecutionId')!r}, expected {fast_qid!r}"
    )
    assert read_exec["Status"]["State"] == "SUCCEEDED", (
        f"getQueryExecution reported state {read_exec['Status']!r} for a query Athena had "
        "already completed"
    )

    rows = output["readResults"]["ResultSet"]["Rows"]
    values = [d.get("VarCharValue") for d in rows[-1]["Data"]]
    assert values == [marker], f"getQueryResults' last row was {values!r}, expected [{marker!r}]"

    stop_output = output["stopQuery"]
    assert stop_output.get("SdkHttpMetadata", {}).get("HttpStatusCode") == 200, (
        f"stopQueryExecution's output was {stop_output!r}"
    )

    # Independent read: Athena's own record shows the stop took effect.
    final = _poll_until(
        lambda: athena.get_query_execution(QueryExecutionId=started_qid)["QueryExecution"],
        lambda qe: qe["Status"]["State"] in ("CANCELLED", "SUCCEEDED", "FAILED"),
        timeout_s=60.0,
    )
    assert final["Status"]["State"] == "CANCELLED", (
        f"Athena reports the stopped query as {final['Status']!r}, expected CANCELLED "
        "(query id ran to completion before the stop task could reach it)"
    )


# ===== helpers =====

def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _best_effort_stop_query(ctx, qid):
    """StopQueryExecution is a no-op (200) on an already-finished query, so it never needs to
    tolerate any particular error code here; anything it does raise is a real cleanup failure."""
    ctx.client("athena").stop_query_execution(QueryExecutionId=qid)


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-athsfn-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK[:200]}]}
    )
    return bucket


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_workgroup(ctx, bucket):
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-behav-wg-")
    athena.create_work_group(
        Name=name,
        Description="sim2real-behav sfn athena direct-call workgroup",
        Configuration={
            "ResultConfiguration": {"OutputLocation": f"s3://{bucket}/results/"},
            "EnforceWorkGroupConfiguration": True,
        },
        Tags=[{"Key": "sim2real", "Value": CHECK[:200]}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True))
    return name


def _run_query_to_completion(ctx, workgroup, query, *, timeout_s=90.0):
    athena = ctx.client("athena")
    qid = athena.start_query_execution(QueryString=query, WorkGroup=workgroup)["QueryExecutionId"]
    ctx.on_cleanup(lambda: _best_effort_stop_query(ctx, qid))
    qe = _poll_until(
        lambda: athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"],
        lambda qe: qe["Status"]["State"] in ("SUCCEEDED", "FAILED", "CANCELLED"),
        timeout_s=timeout_s,
    )
    assert qe["Status"]["State"] == "SUCCEEDED", f"setup query {qid} ended {qe['Status']!r}"
    return qid


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s. Last: {last!r}")


def _create_role(ctx, trust_service, statements):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK[:200]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.put_role_policy(
        RoleName=name, PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"), "NoSuchEntity"))
    return arn


def _create_sfn_role(ctx, bucket, workgroup):
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return _create_role(ctx, "states.amazonaws.com", [
        {
            "Effect": "Allow",
            "Action": ["athena:GetQueryExecution", "athena:GetQueryResults",
                       "athena:StopQueryExecution", "athena:StartQueryExecution"],
            "Resource": f"arn:aws:athena:{ctx.region}:{account_id}:workgroup/{workgroup}",
        },
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:GetBucketLocation"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        },
        {
            "Effect": "Allow",
            "Action": ["glue:GetDatabase", "glue:GetDatabases", "glue:GetTable", "glue:GetTables"],
            "Resource": "*",
        },
    ])


def _create_state_machine(ctx, workgroup, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    definition = {
        "Comment": "sim2real: direct athena getQueryExecution, getQueryResults, stopQueryExecution",
        "StartAt": "ReadExecution",
        "States": {
            "ReadExecution": {
                "Type": "Task",
                "Resource": "arn:aws:states:::athena:getQueryExecution",
                "Parameters": {"QueryExecutionId.$": "$.readQueryId"},
                "ResultPath": "$.readExecution",
                "Next": "ReadResults",
            },
            "ReadResults": {
                "Type": "Task",
                "Resource": "arn:aws:states:::athena:getQueryResults",
                "Parameters": {"QueryExecutionId.$": "$.readQueryId"},
                "ResultPath": "$.readResults",
                "Next": "StartSlowQuery",
            },
            "StartSlowQuery": {
                "Type": "Task",
                "Resource": "arn:aws:states:::athena:startQueryExecution",
                "Parameters": {
                    "QueryString": "SELECT COUNT(*) FROM UNNEST(SEQUENCE(1, 2000000000)) AS t(n)",
                    "WorkGroup.$": "$.workgroup",
                },
                "ResultPath": "$.startSlowQuery",
                "Next": "StopQuery",
            },
            "StopQuery": {
                "Type": "Task",
                "Resource": "arn:aws:states:::athena:stopQueryExecution",
                "Parameters": {"QueryExecutionId.$": "$.startSlowQuery.QueryExecutionId"},
                "ResultPath": "$.stopQuery",
                "End": True,
            },
        },
    }
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn,
                type="STANDARD", tags=[{"key": "sim2real", "value": CHECK[:200]}],
            )["stateMachineArn"]
            ctx.on_cleanup(_teardown(
                lambda: sfn.delete_state_machine(stateMachineArn=arn), "StateMachineDoesNotExist"))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last!r}")


_PROPAGATION_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "UnrecognizedClientException",
    "InvalidClientTokenId",
    "security token included in the request is invalid",
    "is not authorized to perform: athena:",
)


def _start(ctx, sm_arn, payload):
    sfn = ctx.client("stepfunctions")
    arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
        input=json.dumps(payload),
    )["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, arn))
    return arn


def _best_effort_stop(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    try:
        sfn.stop_execution(executionArn=exec_arn, error="sim2real-cleanup", cause="cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _wait_terminal(ctx, exec_arn, *, timeout_s=60.0, interval_s=1.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


def _run_to_terminal(ctx, sm_arn, payload, *, propagation_s=90.0):
    retry_until = time.monotonic() + propagation_s
    while True:
        exec_arn = _start(ctx, sm_arn, payload)
        desc = _wait_terminal(ctx, exec_arn)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _PROPAGATION_MARKERS):
            return exec_arn, desc
        if time.monotonic() >= retry_until:
            return exec_arn, desc
        time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
