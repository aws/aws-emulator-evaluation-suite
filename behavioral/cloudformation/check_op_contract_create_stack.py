"""op-contract-createStack."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-createStack"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]

_BUCKET_TEMPLATE = json.dumps({"Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}}})

_IAM_TEMPLATE = json.dumps(
    {
        "Resources": {
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "lambda.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    }
                },
            }
        }
    }
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateStack returns a StackId DescribeStacks echoes at CREATE_COMPLETE; an IAM template without
    Capabilities fails with InsufficientCapabilitiesException "Requires capabilities : [CAPABILITY_IAM]"
    and registers no stack, and the same template with CAPABILITY_IAM reaches CREATE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cfn-create-")

    resp = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_BUCKET_TEMPLATE,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    stack_id = resp["StackId"]
    assert "cloudformation" in stack_id and f"stack/{stack_name}/" in stack_id
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))

    status = _wait_for_stack_status(
        ctx, stack_name, {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED"}
    )
    assert status == "CREATE_COMPLETE", f"unexpected terminal status {status}"

    described = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert described["StackId"] == stack_id
    assert described["StackName"] == stack_name

    # Error boundary: template with an IAM resource but no acknowledged capabilities.
    other_name = ctx.unique_name("sim2real-cfn-create-iam-")
    code, message = _error(
        lambda: cfn.create_stack(StackName=other_name, TemplateBody=_IAM_TEMPLATE)
    )
    assert code == "InsufficientCapabilitiesException", (
        f"expected InsufficientCapabilitiesException, got {code}"
    )
    assert message == "Requires capabilities : [CAPABILITY_IAM]", (
        f"unexpected InsufficientCapabilitiesException message {message!r}"
    )

    # The rejection is synchronous: no stack is registered under that name.
    not_found_code, not_found_message = _error(lambda: cfn.describe_stacks(StackName=other_name))
    assert not_found_code == "ValidationError", (
        f"expected no stack to exist after the rejected CreateStack, got {not_found_code}"
    )
    assert not_found_message == f"Stack with id {other_name} does not exist", (
        f"unexpected ValidationError message {not_found_message!r}"
    )

    # Restore: the identical template succeeds once the capability is acknowledged.
    ctx.on_cleanup(lambda: _delete_stack(ctx, other_name))
    resp2 = cfn.create_stack(
        StackName=other_name,
        TemplateBody=_IAM_TEMPLATE,
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    assert "cloudformation" in resp2["StackId"] and f"stack/{other_name}/" in resp2["StackId"]
    status2 = _wait_for_stack_status(
        ctx, other_name, {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED"}
    )
    assert status2 == "CREATE_COMPLETE", (
        f"unexpected terminal status after acknowledging capability: {status2}"
    )


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected success raises, so a target
    that accepts input AWS refuses fails as an acceptance rather than as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _wait_for_stack_status(ctx, stack_name, terminal_statuses, timeout_s=240.0, interval_s=4.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        last = resp["Stacks"][0]["StackStatus"]
        if last in terminal_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"stack {stack_name} did not reach {terminal_statuses} in {timeout_s}s (last={last})"
    )


def _delete_stack(ctx, stack_name):
    cfn = ctx.client("cloudformation")
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
