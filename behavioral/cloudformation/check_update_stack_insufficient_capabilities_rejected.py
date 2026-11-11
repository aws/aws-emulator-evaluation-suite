"""update-stack-insufficient-capabilities-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-stack-insufficient-capabilities-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]

_TEMPLATE_BASE = json.dumps({"Resources": {"Topic": {"Type": "AWS::SNS::Topic"}}})
_TEMPLATE_WITH_IAM = json.dumps(
    {
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic"},
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
            },
        }
    }
)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateStack adding an IAM role without CAPABILITY_IAM fails with InsufficientCapabilitiesException,
    leaving the stack in CREATE_COMPLETE with no Role resource; the same update with CAPABILITY_IAM
    reaches UPDATE_COMPLETE and IAM GetRole returns the role (positive control)."""
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    stack_name = ctx.unique_name("sim2real-cfn-updatecap-")
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE_BASE,
        Tags=[{"Key": "owner", "Value": "fidelity"}],
    )
    status = _wait_stack_status(cfn, stack_name, {"CREATE_COMPLETE"}, timeout_s=180)
    assert status == "CREATE_COMPLETE", f"baseline stack never reached CREATE_COMPLETE: {status}"

    # Break: attempt the IAM-adding update without acknowledging the capability.
    error = _error(
        lambda: cfn.update_stack(StackName=stack_name, TemplateBody=_TEMPLATE_WITH_IAM),
        on_success="update_stack without a capability acknowledgement unexpectedly succeeded",
    )
    assert error == ("InsufficientCapabilitiesException", "Requires capabilities : [CAPABILITY_IAM]"), (
        f"expected InsufficientCapabilitiesException 'Requires capabilities : [CAPABILITY_IAM]', "
        f"got {error!r}"
    )

    # Effect absent: the stack's own status is unchanged, and CloudFormation
    # never registered the Role resource at all (independent read, different
    # operation than the rejected UpdateStack).
    status_after = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert status_after == "CREATE_COMPLETE", (
        f"stack status changed despite rejected update: {status_after}"
    )
    role_not_found = _error(
        lambda: cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId="Role"),
        on_success="describe_stack_resource(Role) unexpectedly succeeded after the rejected update",
    )
    expected = ("ValidationError", f"Resource Role does not exist for stack {stack_name}")
    assert role_not_found == expected, (
        f"expected describe_stack_resource(Role) to fail with {expected!r} after the rejected "
        f"update, got {role_not_found!r}"
    )

    # Restore: the identical call, with the capability acknowledged, must succeed.
    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE_WITH_IAM,
        Capabilities=["CAPABILITY_IAM"],
    )
    final_status = _wait_stack_status(
        cfn,
        stack_name,
        {"UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_FAILED"},
        timeout_s=180,
    )
    assert final_status == "UPDATE_COMPLETE", f"restored update ended in {final_status}"

    # Terminal read: independent, and at the destination service, not at CloudFormation.
    role_physical_id = cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId="Role")[
        "StackResourceDetail"
    ]["PhysicalResourceId"]
    role = iam.get_role(RoleName=role_physical_id)["Role"]
    assert role["RoleName"] == role_physical_id, (
        f"IAM does not report the role the restored update created: {role}"
    )


def _error(fn, *, on_success):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises, so a
    target that performs the operation AWS refuses is reported as such, not as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"{on_success}: {result!r}")


def _wait_stack_status(cfn, stack_name, target_statuses, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in target_statuses or not status.endswith("IN_PROGRESS"):
            return status
        time.sleep(interval_s)
    return status


def _delete_stack(cfn, stack_name):
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
