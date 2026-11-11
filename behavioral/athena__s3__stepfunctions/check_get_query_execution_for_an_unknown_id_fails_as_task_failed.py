"""get-query-execution-for-an-unknown-id-fails-as-task-failed."""
from __future__ import annotations

import json
import re
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-query-execution-for-an-unknown-id-fails-as-task-failed"
GROUP = "task_integrations"
SERVICES = ["athena", "s3", "stepfunctions"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A direct athena:getQueryExecution task naming a QueryExecutionId Athena never created
    fails as Athena.InvalidRequestException with the exact not-found message, while the
    identical task against a real, completed query succeeds.
    """
    athena = ctx.client("athena")

    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn)

    bogus_id = str(uuid.uuid4())
    _, desc = _run_to_terminal(ctx, sm_arn, bogus_id)
    assert desc["status"] == "FAILED", (
        f"execution ended {desc['status']!r}, expected FAILED: {desc.get('cause')!r}"
    )
    assert desc["error"] == "Athena.InvalidRequestException", (
        f"the task's error was {desc['error']!r}"
    )
    # AWS relays Athena's error text, which embeds a per-call request id: mask only that id.
    masked = re.sub(r"Request ID: [0-9a-f-]+;", "Request ID: <id>;", desc["cause"])
    assert masked == (
        f"QueryExecution {bogus_id} was not found (Service: AmazonAthena; Status Code: 400; "
        "Error Code: InvalidRequestException; Request ID: <id>; Proxy: null)"
    ), f"the task's cause was {desc['cause']!r}"

    # Positive control: the identical task against a real query execution succeeds.
    bucket = _create_bucket(ctx)
    workgroup = _create_workgroup(ctx, bucket)
    real_id = _run_query_to_completion(ctx, workgroup)
    _, ok_desc = _run_to_terminal(ctx, sm_arn, real_id)
    assert ok_desc["status"] == "SUCCEEDED", (
        f"the real-id sibling ended {ok_desc['status']!r}: "
        f"{ok_desc.get('error')!r} {ok_desc.get('cause')!r}"
    )
    out = json.loads(ok_desc["output"])
    assert out["QueryExecution"]["QueryExecutionId"] == real_id, (
        f"the real-id sibling's output named {out['QueryExecution'].get('QueryExecutionId')!r}"
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


def _run_query_to_completion(ctx, workgroup, *, timeout_s=90.0):
    athena = ctx.client("athena")
    qid = athena.start_query_execution(
        QueryString="SELECT 1", WorkGroup=workgroup,
    )["QueryExecutionId"]
    ctx.on_cleanup(lambda: _best_effort_stop_query(ctx, qid))
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
        if last["Status"]["State"] in ("SUCCEEDED", "FAILED", "CANCELLED"):
            break
        time.sleep(1.0)
    assert last and last["Status"]["State"] == "SUCCEEDED", f"setup query {qid} ended {last!r}"
    return qid


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
        Description="sim2real-behav sfn athena negative-companion workgroup",
        Configuration={
            "ResultConfiguration": {"OutputLocation": f"s3://{bucket}/results/"},
            "EnforceWorkGroupConfiguration": True,
        },
        Tags=[{"Key": "sim2real", "Value": CHECK[:200]}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True))
    return name


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


def _create_sfn_role(ctx):
    return _create_role(ctx, "states.amazonaws.com", [
        {"Effect": "Allow", "Action": "athena:GetQueryExecution", "Resource": "*"},
    ])


def _create_state_machine(ctx, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    definition = {
        "Comment": "sim2real: one direct athena:getQueryExecution task",
        "StartAt": "Read",
        "States": {
            "Read": {
                "Type": "Task",
                "Resource": "arn:aws:states:::athena:getQueryExecution",
                "Parameters": {"QueryExecutionId.$": "$.qid"},
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
    "is not authorized to perform: athena:GetQueryExecution",
)


def _start(ctx, sm_arn, qid):
    sfn = ctx.client("stepfunctions")
    arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
        input=json.dumps({"qid": qid}),
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


def _run_to_terminal(ctx, sm_arn, qid, *, propagation_s=90.0):
    retry_until = time.monotonic() + propagation_s
    while True:
        exec_arn = _start(ctx, sm_arn, qid)
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
