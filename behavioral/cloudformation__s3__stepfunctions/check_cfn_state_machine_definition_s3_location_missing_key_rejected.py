"""cfn-state-machine-definition-s3-location-missing-key-rejected."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-state-machine-definition-s3-location-missing-key-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3", "stepfunctions"]

_DEFINITION = {"StartAt": "S", "States": {"S": {"Type": "Pass", "End": True}}}

_TERMINAL = {
    "CREATE_COMPLETE",
    "CREATE_FAILED",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "DELETE_COMPLETE",
    "DELETE_FAILED",
}
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)
# S3's NoSuchKey as the resource handler's S3 client reports it, request ids masked.
_MISSING_KEY_REASON = (
    "The specified key does not exist. (Service: S3, Status Code: 404, Request ID: <id>, "
    "Extended Request ID: <id>) (SDK Attempt Count: <n>)",
    "GeneralServiceException",
)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(
    ctx, probe, predicate, *, timeout_s: float, interval_s: float = 2.0, description="condition"
):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def masked(text, account):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count and account."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    return text.replace(account, "<account>")


def handler_reason(reason, account):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account), m["code"]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _stack_status(cfn, stack_id: str) -> str:
    """The stack's status read by StackId; the exact not-found pair reads as DELETE_COMPLETE."""
    try:
        return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        err = exc.response["Error"]
        if (err.get("Code"), err.get("Message")) == (
            "ValidationError",
            f"Stack with id {stack_id} does not exist",
        ):
            return "DELETE_COMPLETE"
        raise


def _delete_stack_or_leak(ctx, cfn, stack_id: str) -> None:
    """Delete the stack whatever state it is in, and raise unless it reaches DELETE_COMPLETE."""
    cfn.delete_stack(StackName=stack_id)
    status = _poll_until(
        ctx,
        lambda: _stack_status(cfn, stack_id),
        lambda s: s in {"DELETE_COMPLETE", "DELETE_FAILED"},
        timeout_s=450.0,
        description=f"delete stack {stack_id}",
    )
    if status != "DELETE_COMPLETE":
        raise RuntimeError(f"stack {stack_id} ended {status!r}, not DELETE_COMPLETE")


def _stack_events(cfn, stack_id: str) -> list:
    out = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _template(bucket: str, key: str, sm_name: str, role_name: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "ExecRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": role_name,
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "states.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                    },
                },
                "MyStateMachine": {
                    "Type": "AWS::StepFunctions::StateMachine",
                    "Properties": {
                        "StateMachineName": sm_name,
                        "RoleArn": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                        "DefinitionS3Location": {"Bucket": bucket, "Key": key},
                    },
                },
            },
        }
    )


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:deploy",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A CFN state machine whose DefinitionS3Location names a key absent from the bucket fails
    that resource with S3's NoSuchKey and rolls the stack back, never creating the state
    machine; the same template naming the present key deploys a machine with that definition."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    sfn = ctx.client("stepfunctions")

    bucket = ctx.unique_name("sim2real-behav-sfns3miss-")
    present_key = "definitions/present.asl.json"
    missing_key = "definitions/absent.asl.json"

    create_args = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        create_args["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_args)
    ctx.on_cleanup(_teardown(lambda: s3.delete_bucket(Bucket=bucket), "NoSuchBucket"))
    s3.put_object(Bucket=bucket, Key=present_key, Body=json.dumps(_DEFINITION).encode("utf-8"))
    ctx.on_cleanup(
        _teardown(
            lambda: s3.delete_object(Bucket=bucket, Key=present_key), "NoSuchBucket", "NoSuchKey"
        )
    )

    bad_stack_name = ctx.unique_name("sim2real-behav-sfns3miss-bad-")
    bad_sm_name = ctx.unique_name("sim2real-behav-sfns3miss-sm-bad-")
    bad_role_name = ctx.unique_name("sim2real-behav-sfns3miss-role-bad-")

    bad_stack_id = cfn.create_stack(
        StackName=bad_stack_name,
        TemplateBody=_template(bucket, missing_key, bad_sm_name, bad_role_name),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_or_leak(ctx, cfn, bad_stack_id))

    status = _poll_until(
        ctx,
        lambda: _stack_status(cfn, bad_stack_id),
        lambda s: s in _TERMINAL,
        timeout_s=300.0,
        description=f"stack {bad_stack_name} terminal",
    )
    assert status == "ROLLBACK_COMPLETE", (
        f"stack whose DefinitionS3Location key does not exist ended in {status!r}, "
        f"expected ROLLBACK_COMPLETE"
    )

    hits = [
        e
        for e in _stack_events(cfn, bad_stack_id)
        if e["LogicalResourceId"] == "MyStateMachine" and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert len(hits) == 1, (
        f"expected exactly one CREATE_FAILED event for MyStateMachine, got {len(hits)}"
    )
    got = handler_reason(hits[0].get("ResourceStatusReason"), ctx.account)
    assert got == _MISSING_KEY_REASON, (
        f"MyStateMachine's CREATE_FAILED reason: expected {_MISSING_KEY_REASON!r}, got {got!r}"
    )

    bad_sm_arn = f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:{bad_sm_name}"
    code, message = _error(lambda: sfn.describe_state_machine(stateMachineArn=bad_sm_arn))
    expected = ("StateMachineDoesNotExist", f"State Machine Does Not Exist: '{bad_sm_arn}'")
    assert (code, message) == expected, f"expected {expected!r}, got {(code, message)!r}"

    good_stack_name = ctx.unique_name("sim2real-behav-sfns3miss-good-")
    good_sm_name = ctx.unique_name("sim2real-behav-sfns3miss-sm-good-")
    good_role_name = ctx.unique_name("sim2real-behav-sfns3miss-role-good-")

    good_stack_id = cfn.create_stack(
        StackName=good_stack_name,
        TemplateBody=_template(bucket, present_key, good_sm_name, good_role_name),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_or_leak(ctx, cfn, good_stack_id))
    good_status = _poll_until(
        ctx,
        lambda: _stack_status(cfn, good_stack_id),
        lambda s: s in _TERMINAL,
        timeout_s=450.0,
        description=f"stack {good_stack_name} terminal",
    )
    assert good_status == "CREATE_COMPLETE", (
        f"positive control with the real S3 key ended in {good_status!r}, expected CREATE_COMPLETE "
        f"— the rejection above must be about the missing key, not the bucket or account"
    )
    good_sm_arn = f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:{good_sm_name}"
    described = sfn.describe_state_machine(stateMachineArn=good_sm_arn)
    assert json.loads(described["definition"]) == _DEFINITION, (
        f"expected the definition read from the present key, got {described['definition']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
