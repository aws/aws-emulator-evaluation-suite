"""describe-stack-refactor-not-found-error."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-stack-refactor-not-found-error"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeStackRefactor on a REAL refactor id succeeds (positive control); the
    identical call with an unknown id instead returns StackRefactorNotFoundException."""
    cfn = ctx.client("cloudformation")

    stack_name = ctx.unique_name("sim2real-refactor-notfound-")
    old_logical_id = "TopicOld"
    new_logical_id = "TopicNew"

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(_sns_template(old_logical_id)),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_stack(cfn, stack_name))
    _wait_stack_terminal(cfn, stack_name)

    try:
        real_id = cfn.create_stack_refactor(
            StackDefinitions=[
                {"StackName": stack_name, "TemplateBody": json.dumps(_sns_template(new_logical_id))}
            ],
            ResourceMappings=[
                {
                    "Source": {"StackName": stack_name, "LogicalResourceId": old_logical_id},
                    "Destination": {"StackName": stack_name, "LogicalResourceId": new_logical_id},
                }
            ],
        )["StackRefactorId"]
    except ClientError as exc:
        raise AssertionError(f"CreateStackRefactor rejected a well-formed refactor request: {exc}") from exc

    # Positive control: the real id must be describable. Without this leg, a target that
    # answers StackRefactorNotFoundException to every DescribeStackRefactor call — real id
    # included — would pass the negative below for the wrong reason.
    real_described = _describe_with_retry(cfn, real_id)
    assert real_described["StackRefactorId"] == real_id, real_described
    assert "Status" in real_described, real_described

    # Derive the bogus id from the real one rather than an unrelated random value, so a
    # correctly-scoped IAM/resource check on the real id's shape cannot mask the not-found
    # semantics we are actually measuring.
    bogus_id = real_id + "-notfound"
    code, msg = _client_error(
        lambda: cfn.describe_stack_refactor(StackRefactorId=bogus_id),
        "DescribeStackRefactor of an unknown id",
    )
    assert code == "StackRefactorNotFoundException", (
        f"expected StackRefactorNotFoundException, got {code}"
    )
    assert msg == f"Stack refactor [{bogus_id}] does not exist", msg


def _sns_template(logical_id: str) -> dict:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {logical_id: {"Type": "AWS::SNS::Topic", "Properties": {}}},
    }


def _client_error(fn, what):
    """Return (code, message) of the ClientError `fn` raises; raise AssertionError if it succeeds."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"].get("Code"), err.response["Error"].get("Message")
    raise AssertionError(f"expected {what} to be rejected, but the call succeeded")


def _describe_with_retry(cfn, refactor_id: str, timeout_s: float = 30.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return cfn.describe_stack_refactor(StackRefactorId=refactor_id)
        except ClientError as exc:
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"real refactor id never became describable within {timeout_s}s: {last_err}")


def _wait_stack_terminal(cfn, stack_name: str, timeout_s: float = 180.0, interval_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status == "CREATE_COMPLETE":
            return
        if status in ("CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"):
            raise AssertionError(f"prerequisite stack {stack_name} ended in {status}")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach CREATE_COMPLETE within {timeout_s}s, last={status}")


def _safe_delete_stack(cfn, stack_name: str) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
