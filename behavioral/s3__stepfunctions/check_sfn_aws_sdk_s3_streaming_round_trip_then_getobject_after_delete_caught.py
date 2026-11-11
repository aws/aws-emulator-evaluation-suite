"""sfn-aws-sdk-s3-streaming-round-trip-then-getobject-after-delete-caught."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-aws-sdk-s3-streaming-round-trip-then-getobject-after-delete-caught"
GROUP = "task_integrations"
SERVICES = ["s3", "stepfunctions"]

_BODY = "sim2real-s3-roundtrip-payload"


@tags("axis:happy-path", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "cap:c3")
def run(ctx) -> None:
    """A Task chain of aws-sdk headBucket, putObject, getObject and deleteObject round-trips a
    real object; a getObject repeated after the delete fails S3.NoSuchKeyException, and a Catch
    carries that error into the execution's own output instead of failing the execution.
    """
    bucket = _create_bucket(ctx)
    key = "roundtrip.txt"
    role_arn = _create_role(ctx, [
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
         "Resource": f"arn:aws:s3:::{bucket}/*"},
        {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": f"arn:aws:s3:::{bucket}"},
    ])
    sm_arn = _create_state_machine(ctx, {
        "Comment": "headBucket, putObject, getObject, deleteObject, then getObject again",
        "StartAt": "Head",
        "States": {
            "Head": {
                "Type": "Task", "Resource": "arn:aws:states:::aws-sdk:s3:headBucket",
                "Parameters": {"Bucket": bucket}, "ResultPath": "$.head", "Next": "Put",
            },
            "Put": {
                "Type": "Task", "Resource": "arn:aws:states:::aws-sdk:s3:putObject",
                "Parameters": {"Bucket": bucket, "Key": key, "Body": _BODY},
                "ResultPath": "$.put", "Next": "Get",
            },
            "Get": {
                "Type": "Task", "Resource": "arn:aws:states:::aws-sdk:s3:getObject",
                "Parameters": {"Bucket": bucket, "Key": key},
                "ResultSelector": {"content.$": "$.Body"}, "ResultPath": "$.get", "Next": "Delete",
            },
            "Delete": {
                "Type": "Task", "Resource": "arn:aws:states:::aws-sdk:s3:deleteObject",
                "Parameters": {"Bucket": bucket, "Key": key},
                "ResultPath": "$.delete", "Next": "GetAgain",
            },
            "GetAgain": {
                "Type": "Task", "Resource": "arn:aws:states:::aws-sdk:s3:getObject",
                "Parameters": {"Bucket": bucket, "Key": key},
                "Catch": [{"ErrorEquals": ["States.TaskFailed"], "ResultPath": "$.errorInfo",
                           "Next": "Done"}],
                "End": True,
            },
            "Done": {"Type": "Pass", "End": True},
        },
    }, role_arn)

    exe, output = _run_past_propagation(ctx, sm_arn)
    assert exe["status"] == "SUCCEEDED", (
        f"the round trip ended {exe['status']!r}: {exe.get('error')!r} {exe.get('cause')!r}"
    )

    assert output["head"]["BucketArn"] == f"arn:aws:s3:::{bucket}", (
        f"headBucket named the wrong bucket: {output['head']!r}"
    )
    assert "ETag" in output["put"], f"putObject returned no ETag: {output['put']!r}"
    # aws-sdk:s3:putObject JSON-serializes a string Body, so the stored (and re-fetched) content
    # is the JSON-quoted payload.
    assert output["get"]["content"] == json.dumps(_BODY), (
        f"getObject before the delete did not return the written payload: {output['get']!r}"
    )

    error_info = output.get("errorInfo")
    assert error_info is not None, f"no errorInfo was caught after the delete: {output!r}"
    assert error_info.get("Error") == "S3.NoSuchKeyException", (
        f"expected the post-delete getObject to fail S3.NoSuchKeyException, caught as "
        f"{error_info!r}"
    )
    assert error_info.get("Cause"), f"the caught error carried no Cause: {error_info!r}"

    # Positive control: the object is genuinely gone, not merely reported so by the Catch.
    s3 = ctx.client("s3")
    code, message = _error(lambda: s3.get_object(Bucket=bucket, Key=key))
    assert code == "NoSuchKey", (
        f"a direct S3 read also expected NoSuchKey after the delete, got {code!r}"
    )
    assert message == "The specified key does not exist.", (
        f"expected message 'The specified key does not exist.', got {message!r}"
    )


# ===== helpers =====
_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")
_ROLE_PROPAGATION_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "is not authorized to perform: sts:AssumeRole",
    "AccessDenied",
)


def _error(fn) -> tuple[str, str]:
    """The (Error.Code, Error.Message) ``fn`` raises. An unexpected success raises too, naming
    what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-sfns3rt-")
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
    role_name = ctx.unique_name("sim2real-behav-sfns3rtrole-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    })
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust,
        Description="sim2real-behav sfn aws-sdk s3 streaming round-trip execution role",
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
    name = ctx.unique_name("sim2real-behav-s3rtsm-")
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


def _run_past_propagation(ctx, sm_arn, *, outer_attempts=6):
    """Run to terminal, then re-run on a fresh execution if the Catch on GetAgain swallowed a
    role-propagation race (States.TaskFailed: not yet authorized to assume) instead of the
    S3.NoSuchKeyException under test — that race can still land on a task several states in,
    even once earlier tasks using the same role have already succeeded."""
    desc, output = None, None
    for _ in range(outer_attempts):
        desc = _run_to_terminal(ctx, sm_arn, {})
        if desc["status"] != "SUCCEEDED":
            return desc, {}
        output = json.loads(desc["output"])
        error_info = output.get("errorInfo") or {}
        cause = error_info.get("Cause") or ""
        if error_info.get("Error") != "S3.NoSuchKeyException" and any(
            m in cause for m in _ROLE_PROPAGATION_MARKERS
        ):
            time.sleep(5)
            continue
        return desc, output
    return desc, output


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
