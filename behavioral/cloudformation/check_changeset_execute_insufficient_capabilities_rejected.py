"""changeset-execute-insufficient-capabilities-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "changeset-execute-insufficient-capabilities-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]

_TEMPLATE_BASE = json.dumps(
    {"Resources": {"Topic": {"Type": "AWS::SNS::Topic"}}}
)
_TEMPLATE_BASE_PLUS_TOPIC = json.dumps(
    {
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic"},
            "Topic2": {"Type": "AWS::SNS::Topic"},
        }
    }
)
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


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateChangeSet for an IAM-touching UPDATE without Capabilities is refused with
    InsufficientCapabilitiesException and "Requires capabilities : [CAPABILITY_IAM]" and leaves no
    change set, while a non-IAM update and the same call with CAPABILITY_IAM both succeed."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cfn-execcap-")
    cs_name = ctx.unique_name("sim2real-cs-")
    cs_name_ok = ctx.unique_name("sim2real-cs-ok-")
    ctx.on_cleanup(lambda: _cleanup(cfn, stack_name, cs_name, cs_name_ok))

    cfn.create_stack(StackName=stack_name, TemplateBody=_TEMPLATE_BASE)
    baseline_status = _wait_stack_status(cfn, stack_name, {"CREATE_COMPLETE"}, timeout_s=180)
    assert baseline_status == "CREATE_COMPLETE", (
        f"baseline stack never reached CREATE_COMPLETE: {baseline_status}"
    )

    # Positive control: an UPDATE-type change set whose diff never touches IAM needs no
    # capability acknowledgement at all, so CreateChangeSet must succeed here without Capabilities.
    cfn.create_change_set(
        StackName=stack_name,
        ChangeSetName=cs_name_ok,
        ChangeSetType="UPDATE",
        TemplateBody=_TEMPLATE_BASE_PLUS_TOPIC,
    )
    control_status = _wait_change_set_status(
        cfn, cs_name_ok, stack_name, {"CREATE_COMPLETE", "FAILED"}, timeout_s=120
    )
    assert control_status == "CREATE_COMPLETE", (
        f"positive control (no IAM diff, no Capabilities) did not reach CREATE_COMPLETE: "
        f"{control_status}"
    )
    cfn.delete_change_set(ChangeSetName=cs_name_ok, StackName=stack_name)

    # Capabilities omitted: CreateChangeSet already sees the IAM-touching diff and refuses it.
    code, msg = _client_error(
        lambda: cfn.create_change_set(
            StackName=stack_name,
            ChangeSetName=cs_name,
            ChangeSetType="UPDATE",
            TemplateBody=_TEMPLATE_WITH_IAM,
        ),
        "CreateChangeSet of an IAM-touching update without Capabilities",
    )
    assert code == "InsufficientCapabilitiesException", code
    assert msg == "Requires capabilities : [CAPABILITY_IAM]", msg

    # Effect absent: the rejected call left no change set behind.
    describe_code, describe_msg = _client_error(
        lambda: cfn.describe_change_set(ChangeSetName=cs_name, StackName=stack_name),
        "DescribeChangeSet of the change set the rejected call named",
    )
    assert describe_code == "ChangeSetNotFound", (
        f"expected no change set to exist after rejection, got describe code {describe_code!r}"
    )
    assert describe_msg == f"ChangeSet [{cs_name}] does not exist", describe_msg

    # Restore: the identical call succeeds once the capability is acknowledged.
    cfn.create_change_set(
        StackName=stack_name,
        ChangeSetName=cs_name,
        ChangeSetType="UPDATE",
        TemplateBody=_TEMPLATE_WITH_IAM,
        Capabilities=["CAPABILITY_IAM"],
    )
    restored_status = _wait_change_set_status(
        cfn, cs_name, stack_name, {"CREATE_COMPLETE", "FAILED"}, timeout_s=120
    )
    assert restored_status == "CREATE_COMPLETE", (
        f"the identical call with CAPABILITY_IAM acknowledged did not reach CREATE_COMPLETE: "
        f"{restored_status}"
    )


def _client_error(fn, what):
    """Return (code, message) of the ClientError `fn` raises; raise AssertionError if it succeeds."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"].get("Code"), err.response["Error"].get("Message")
    raise AssertionError(f"expected {what} to be rejected, but the call succeeded")


def _wait_stack_status(cfn, stack_name, target_statuses, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in target_statuses or not status.endswith("IN_PROGRESS"):
            return status
        time.sleep(interval_s)
    return status


def _wait_change_set_status(cfn, cs_name, stack_name, target_statuses, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_change_set(ChangeSetName=cs_name, StackName=stack_name)["Status"]
        if status in target_statuses:
            return status
        time.sleep(interval_s)
    return status


def _cleanup(cfn, stack_name, cs_name, cs_name_ok):
    for name in (cs_name, cs_name_ok):
        try:
            cfn.delete_change_set(ChangeSetName=name, StackName=stack_name)
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] in ("ChangeSetNotFound",) or
                (exc.response["Error"]["Code"] == "ValidationError"
                 and "does not exist" in exc.response["Error"].get("Message", ""))
            ):
                raise
    try:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
