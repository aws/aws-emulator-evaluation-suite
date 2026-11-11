"""iam-role-missing-trust-policy-action-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-role-missing-trust-policy-action-rejected"
GROUP = "resource-existence"
SERVICES = ["cloudformation", "iam"]

_STACK_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}

# CloudFormation's resource-handler wrapping of the service error; the request id and token vary.
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*) \(Service: (?P<service>[A-Za-z0-9]+), '
    r'Status Code: (?P<status>\d+), Request ID: [^)]*\)(?: \(SDK Attempt Count: \d+\))?" '
    r'\(RequestToken: [^,]*, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$'
)


def _wait_stack(cfn, stack_id: str, *, timeout_s: float = 240.0, interval_s: float = 2.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last in _STACK_TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_id!r} not terminal within {timeout_s}s (last={last!r})")


def _resource_failure(cfn, stack_id: str, logical_id: str) -> tuple[str, str, str, str]:
    """``(message, service, status, HandlerErrorCode)`` from the CREATE_FAILED event for *logical_id*."""
    for event in cfn.describe_stack_events(StackName=stack_id)["StackEvents"]:
        if event["LogicalResourceId"] != logical_id or event["ResourceStatus"] != "CREATE_FAILED":
            continue
        reason = event.get("ResourceStatusReason", "")
        match = _HANDLER_REASON.match(reason)
        if match:
            return match["message"], match["service"], match["status"], match["code"]
        raise AssertionError(f"could not parse handler reason: {reason!r}")
    raise AssertionError(f"no CREATE_FAILED event for {logical_id!r} in stack {stack_id!r}")


def _delete_stack_and_wait(cfn, stack_id: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cfn.delete_stack(StackName=stack_id)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": 25}
    )


def _no_such_role(iam, role_name: str) -> None:
    """GetRole answers IAM's exact NoSuchEntity for ``role_name``."""
    try:
        iam.get_role(RoleName=role_name)
    except ClientError as exc:
        got = (exc.response["Error"]["Code"], exc.response["Error"]["Message"])
    else:
        raise AssertionError(f"role {role_name!r} unexpectedly exists")
    assert got == ("NoSuchEntity", f"The role with name {role_name} cannot be found."), (
        f"GetRole on {role_name!r}: {got!r}"
    )


@tags("axis:rejection", "cap:c7", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::IAM::Role whose trust policy statement omits the required Action
    rolls back with IAM's error and no role ever created; the same template with an Action deploys."""
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")

    bad_role_name = ctx.unique_name("sim2real-behav-cfn-iambad-")
    bad_stack_name = ctx.unique_name("sim2real-behav-cfn-iambad-")
    bad_stack_id = cfn.create_stack(
        StackName=bad_stack_name,
        TemplateBody=json.dumps({
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Role": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": bad_role_name,
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Principal": {"Service": "lambda.amazonaws.com"},
                            }],
                        },
                    },
                },
            },
        }),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, bad_stack_id))

    status = _wait_stack(cfn, bad_stack_id)
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {status!r}"

    got_error = _resource_failure(cfn, bad_stack_id, "Role")
    want_error = ("Missing required field Action", "Iam", "400", "InvalidRequest")
    assert got_error == want_error, f"CREATE_FAILED reason: expected {want_error!r}, got {got_error!r}"
    _no_such_role(iam, bad_role_name)

    # Positive control, in the same file: a validly-configured role deploys cleanly.
    good_role_name = ctx.unique_name("sim2real-behav-cfn-iamok-")
    good_stack_name = ctx.unique_name("sim2real-behav-cfn-iamok-")
    good_stack_id = cfn.create_stack(
        StackName=good_stack_name,
        TemplateBody=json.dumps({
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Role": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": good_role_name,
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Principal": {"Service": "lambda.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }],
                        },
                    },
                },
            },
        }),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, good_stack_id))
    good_status = _wait_stack(cfn, good_stack_id)
    assert good_status == "CREATE_COMPLETE", f"control stack: expected CREATE_COMPLETE, got {good_status!r}"
    iam.get_role(RoleName=good_role_name)  # control: the valid role is real

    for stack_id in (bad_stack_id, good_stack_id):
        _delete_stack_and_wait(cfn, stack_id)
        final = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        assert final == "DELETE_COMPLETE", f"stack {stack_id} delete ended {final!r}"
    _no_such_role(iam, good_role_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
