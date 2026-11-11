"""delete-stack-retain-resources-leaves-the-retained-bucket-intact."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-stack-retain-resources-leaves-the-retained-bucket-intact"
GROUP = "stack_lifecycle"
SERVICES = ["cloudformation"]

STACK_TIMEOUT_S = 300.0
_PARAM_NOT_FOUND = "ParameterNotFound"
_BUCKET_NOT_EMPTY_REASON = (
    r'Resource handler returned message: "The bucket you tried to delete is not empty '
    r'\(Service: S3, Status Code: 409, Request ID: [A-Z0-9]+, Extended Request ID: [A-Za-z0-9+/=]+\) '
    r'\(SDK Attempt Count: \d+\)" \(RequestToken: [0-9a-f-]{36}, HandlerErrorCode: GeneralServiceException\)'
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteStack(RetainResources=[...]) on a DELETE_FAILED stack must delete the stack while
    leaving the named resource and its contents physically intact."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    ssm = ctx.client("ssm")
    tag = [{"Key": "sim2real-check", "Value": CHECK}]

    stack = ctx.unique_name("sim2real-cfn-retain-")
    companion_name = "/" + ctx.unique_name("sim2real-cfn-retain-companion-")
    companion_value = ctx.unique_name("companion-")
    key = "sim2real/retained-object"
    body = ctx.unique_name("retained-body-").encode("utf-8")

    stack_id = cfn.create_stack(
        StackName=stack, TemplateBody=_template(companion_name, companion_value), Tags=tag
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cfn, stack_id, retain=("Bucket",)))
    created = _poll_status(
        cfn, stack, {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED"}, why="prerequisite create"
    )
    assert created == "CREATE_COMPLETE", f"stack {stack!r}: expected CREATE_COMPLETE, got {created!r}"

    bucket = _physical_id(cfn, stack, "Bucket")
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    # Make the bucket undeletable by CloudFormation. This is the documented reason RetainResources
    # exists, so it is the experiment rather than a contrivance.
    s3.put_object(Bucket=bucket, Key=key, Body=body)
    assert companion_value == _param_value(ssm, companion_name), (
        f"companion parameter {companion_name!r}: expected {companion_value!r} after create, got "
        f"{_param_value(ssm, companion_name)!r}"
    )

    # --- Beat 1: the plain DeleteStack must fail, and must fail ON THE BUCKET --------------------
    cfn.delete_stack(StackName=stack)
    failed = _poll_status(
        cfn, stack, {"DELETE_FAILED", "DELETE_COMPLETE", "GONE"}, why="delete of a non-empty bucket"
    )
    assert failed == "DELETE_FAILED", (
        f"deleting a stack whose S3 bucket is non-empty must settle in DELETE_FAILED, got {failed!r}; "
        "DELETE_COMPLETE here means the bucket and its object were destroyed"
    )
    bucket_reason = _resource_failure_reason(cfn, stack, "Bucket")
    # The handler reason embeds the per-call S3 Request ID, Extended Request ID and the
    # CloudFormation RequestToken, so those parts are graded by form.
    assert re.fullmatch(_BUCKET_NOT_EMPTY_REASON, bucket_reason), (
        f"the Bucket resource's failure reason should match {_BUCKET_NOT_EMPTY_REASON!r}, got "
        f"{bucket_reason!r}"
    )

    # --- Beat 2: positive control — the delete really did run and removed what it could ----------
    # Without this, "the bucket survived" is indistinguishable from "a target that deletes nothing".
    companion_got = _expect_error(lambda: ssm.get_parameter(Name=companion_name))
    companion_expected = (_PARAM_NOT_FOUND, "")
    assert companion_got == companion_expected, (
        f"the failed delete must still have removed the companion parameter {companion_name!r}; "
        f"ssm:GetParameter returned {companion_got!r}, expected {companion_expected!r}"
    )

    # --- Beat 3: retry the delete, retaining exactly the resource that blocked it -----------------
    cfn.delete_stack(StackName=stack, RetainResources=["Bucket"])
    deleted = _poll_status(cfn, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, why="retained delete")
    assert deleted == "DELETE_COMPLETE", (
        f"DeleteStack(RetainResources=['Bucket']) must complete, got {deleted!r} "
        f"(reason={_status_reason(cfn, stack_id)!r})"
    )

    # --- Beat 4: terminal read at the destination — the retained resource is INTACT --------------
    # A different operation, at a different service, than the one that mutated. The bucket must
    # still exist AND still hold the exact bytes: a target that "retains" a name while dropping
    # contents fails the second half.
    got = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert got == body, (
        f"retained bucket {bucket!r} object {key!r}: expected the original {body!r}, got {got!r}"
    )
    listed = {o["Key"] for o in s3.list_objects_v2(Bucket=bucket).get("Contents", [])}
    assert listed == {key}, (
        f"retained bucket {bucket!r} should list exactly {{{key!r}}}, got {sorted(listed)!r}"
    )

    # --- Beat 5: the stack itself is gone and unusable --------------------------------------
    not_found = ("ValidationError", f"Stack with id {stack} does not exist")
    stack_got = _expect_error(lambda: cfn.describe_stacks(StackName=stack))
    assert stack_got == not_found, (
        f"DescribeStacks on the deleted stack: expected {not_found!r}, got {stack_got!r}"
    )
    mutate_got = _expect_error(
        lambda: cfn.update_stack(StackName=stack, TemplateBody=_template(companion_name, companion_value))
    )
    mutate_expected = ("ValidationError", f"Stack [{stack}] does not exist")
    assert mutate_got == mutate_expected, (
        f"UpdateStack on the deleted stack: expected {mutate_expected!r}, got {mutate_got!r}"
    )


def _template(companion_name: str, companion_value: str) -> str:
    """One bucket that will block the delete, and one companion resource that must not.

    The bucket name is auto-generated so nothing here depends on a name the check did not create.
    """
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Bucket": {"Type": "AWS::S3::Bucket"},
                "Companion": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": companion_name, "Type": "String", "Value": companion_value},
                },
            },
        }
    )


def _status(cfn, stack_name: str) -> str:
    """The stack's status, or "GONE" when DescribeStacks says it does not exist."""
    try:
        return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ValidationError":
            return "GONE"
        raise


def _poll_status(cfn, stack_name: str, terminal: set[str], *, why: str) -> str:
    """Bounded retry with a deadline; RAISES on timeout rather than returning the last value."""
    deadline = time.monotonic() + STACK_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = _status(cfn, stack_name)
        if last in terminal:
            return last
        time.sleep(4.0)
    raise AssertionError(
        f"stack {stack_name!r} did not reach any of {sorted(terminal)!r} within {STACK_TIMEOUT_S}s "
        f"[{why}] (last={last!r})"
    )


def _status_reason(cfn, stack_name: str) -> str:
    try:
        return cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("StackStatusReason") or ""
    except ClientError:
        return "<stack gone>"


def _physical_id(cfn, stack_name: str, logical_id: str) -> str:
    detail = cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId=logical_id)
    return detail["StackResourceDetail"]["PhysicalResourceId"]


def _resource_failure_reason(cfn, stack_name: str, logical_id: str) -> str:
    """The reason on the most recent DELETE_FAILED event for one logical id."""
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name):
        for event in page["StackEvents"]:
            if (
                event.get("LogicalResourceId") == logical_id
                and event.get("ResourceStatus") == "DELETE_FAILED"
            ):
                return event.get("ResourceStatusReason") or "<empty ResourceStatusReason>"
    raise AssertionError(
        f"stack {stack_name!r} has no DELETE_FAILED event for logical id {logical_id!r}; expected the "
        "non-empty bucket to be named as the reason the delete failed"
    )


def _param_value(ssm, name: str) -> str:
    return ssm.get_parameter(Name=name)["Parameter"]["Value"]


def _expect_error(fn) -> tuple:
    """(Error.Code, Error.Message) raised by fn(); RAISES if fn() unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", "<no code>"), err.get("Message")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    """Teardown only, scoped to the one bucket this check created (never a prefix sweep)."""
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _teardown_stack(cfn, stack_id: str, *, retain: tuple[str, ...] = (), timeout_s: float = 600.0) -> None:
    """Delete the stack by StackId and poll to DELETE_COMPLETE; a DELETE_FAILED stack is deleted
    again retaining ``retain``, and a second DELETE_FAILED or a timeout raises."""
    for attempt in range(2):
        prior = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if prior == "DELETE_COMPLETE":
            return
        if prior == "DELETE_FAILED" and retain:
            cfn.delete_stack(StackName=stack_id, RetainResources=list(retain))
        else:
            cfn.delete_stack(StackName=stack_id)
        deadline = time.monotonic() + timeout_s
        moved = False
        while True:
            stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
            status = stack["StackStatus"]
            moved = moved or status != prior
            if status == "DELETE_COMPLETE":
                return
            if status == "DELETE_FAILED" and moved:
                if attempt == 0 and retain:
                    break
                raise AssertionError(
                    f"stack {stack_id} teardown ended DELETE_FAILED: {stack.get('StackStatusReason')!r}"
                )
            if time.monotonic() > deadline:
                raise AssertionError(f"stack {stack_id} still {status} {timeout_s}s after DeleteStack")
            time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
