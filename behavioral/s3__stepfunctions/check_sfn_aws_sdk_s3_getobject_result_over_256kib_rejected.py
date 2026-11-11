"""sfn-aws-sdk-s3-getobject-result-over-256kib-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-aws-sdk-s3-getobject-result-over-256kib-rejected"
GROUP = "task_integrations"
SERVICES = ["s3", "stepfunctions"]

_UNDER = 200 * 1024
_OVER = 300 * 1024


@tags("axis:rejection", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "cap:c3")
def run(ctx) -> None:
    """An aws-sdk:s3:getObject result over 256 KiB fails the execution with
    States.DataLimitExceeded and its exact cause, naming the integration itself (not the
    object); the same ResultSelector succeeds intact for a 200 KiB object.
    """
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    small_key, big_key = "small.bin", "big.bin"
    small_body = "s" * _UNDER
    s3.put_object(Bucket=bucket, Key=small_key, Body=small_body.encode())
    s3.put_object(Bucket=bucket, Key=big_key, Body=("b" * _OVER).encode())

    role_arn = _create_role(ctx, [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/*"},
    ])
    sm_arn = _create_state_machine(ctx, {
        "Comment": "fetch an S3 object through the aws-sdk integration, narrowed to its body",
        "StartAt": "Get",
        "States": {"Get": {
            "Type": "Task",
            "Resource": "arn:aws:states:::aws-sdk:s3:getObject",
            "Parameters": {"Bucket": bucket, "Key.$": "$.key"},
            "ResultSelector": {"content.$": "$.Body"},
            "End": True,
        }},
    }, role_arn)

    ok = _run_to_terminal(ctx, sm_arn, {"key": small_key})
    assert ok["status"] == "SUCCEEDED", (
        f"positive control: getting a {_UNDER}-byte object ended {ok['status']!r}: "
        f"{ok.get('error')!r} {ok.get('cause')!r}"
    )
    assert json.loads(ok["output"]) == {"content": small_body}, (
        f"the {_UNDER}-byte object did not arrive intact through ResultSelector "
        f"(output was {ok.get('output')!r})"
    )

    bad = _run_to_terminal(ctx, sm_arn, {"key": big_key})
    assert bad["status"] == "FAILED", f"a {_OVER}-byte result ended {bad['status']!r}, expected FAILED"
    assert bad.get("error") == "States.DataLimitExceeded", (
        f"the oversize result failed with {bad.get('error')!r} ({bad.get('cause')!r}), "
        f"expected States.DataLimitExceeded"
    )
    expected_cause = (
        "The state/task 'aws-sdk:s3' returned a result with a size exceeding the maximum "
        "number of bytes service limit."
    )
    assert bad.get("cause") == expected_cause, f"expected cause {expected_cause!r}, got {bad.get('cause')!r}"
    assert bad.get("output") is None, "the refused execution produced output"

    events = _history(ctx, bad["executionArn"])
    types = [e["type"] for e in events]
    assert "TaskSucceeded" not in types and "TaskStateExited" not in types, (
        f"the oversize result was recorded as a task result: {types!r}"
    )
    failed = [e["executionFailedEventDetails"] for e in events if e["type"] == "ExecutionFailed"]
    assert len(failed) == 1 and failed[0].get("error") == "States.DataLimitExceeded", (
        f"ExecutionFailed was {failed!r}"
    )
    assert failed[0].get("cause") == expected_cause, (
        f"expected ExecutionFailed cause {expected_cause!r}, got {failed[0].get('cause')!r}"
    )


# ===== helpers =====
_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")
_ROLE_PROPAGATION_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "is not authorized to perform: sts:AssumeRole",
    "AccessDenied",
)


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-sfns3get-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
    s3.delete_bucket(Bucket=bucket)


def _create_role(ctx, statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfns3role-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    })
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust,
        Description="sim2real-behav sfn aws-sdk s3 getObject execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    iam.put_role_policy(
        RoleName=role_name, PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    # IAM propagation exposes no condition to poll; the bounded retry in _run_to_terminal absorbs it.
    return role_arn


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-s3getsm-")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the role: {last!r}")


def _best_effort_stop(ctx, exec_arn):
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="SimCleanup", cause="sim2real cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _poll(probe, predicate, *, timeout_s, what, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what}: not reached within {timeout_s}s; last={last!r}")


def _run_to_terminal(ctx, sm_arn, payload, *, timeout_s=120, attempts=8):
    sfn = ctx.client("stepfunctions")
    desc = None
    for _ in range(attempts):
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
            input=json.dumps(payload),
        )["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: _best_effort_stop(ctx, a))
        desc = _poll(lambda a=exec_arn: sfn.describe_execution(executionArn=a),
                     lambda d: d["status"] in _TERMINAL, timeout_s=timeout_s,
                     what=f"execution {exec_arn} terminal")
        blob = (desc.get("error") or "") + (desc.get("cause") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _ROLE_PROPAGATION_MARKERS):
            return desc
        time.sleep(5)
    return desc


def _history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    events, kwargs = [], {"executionArn": exec_arn, "maxResults": 1000}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        events.extend(resp["events"])
        if not resp.get("nextToken"):
            return events
        kwargs["nextToken"] = resp["nextToken"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
