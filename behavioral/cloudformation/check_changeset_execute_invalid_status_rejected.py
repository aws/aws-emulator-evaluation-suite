"""changeset-execute-invalid-status-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "changeset-execute-invalid-status-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]

# The macro Lambda sleeps before returning the fragment unchanged, so the change set that
# references it stays in CREATE_IN_PROGRESS for that long: the check holds the window
# instead of racing the change set to CREATE_COMPLETE.
_MACRO_HOLD_S = 90

_MACRO_CODE = """import time


def handler(event, context):
    time.sleep(%d)
    return {
        "requestId": event["requestId"],
        "status": "success",
        "fragment": event["fragment"],
    }
""" % _MACRO_HOLD_S


def _macro_template(macro_name: str) -> str:
    return json.dumps(
        {
            "Resources": {
                "MacroRole": {
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
                "MacroFunction": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "Runtime": "python3.12",
                        "Handler": "index.handler",
                        "Role": {"Fn::GetAtt": ["MacroRole", "Arn"]},
                        "Timeout": _MACRO_HOLD_S + 60,
                        "Code": {"ZipFile": _MACRO_CODE},
                    },
                },
                "Macro": {
                    "Type": "AWS::CloudFormation::Macro",
                    "Properties": {
                        "Name": macro_name,
                        "FunctionName": {"Fn::GetAtt": ["MacroFunction", "Arn"]},
                    },
                },
            }
        }
    )


def _template(topic_name: str, macro_name: str) -> str:
    return json.dumps(
        {
            "Transform": macro_name,
            "Resources": {
                "Topic": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": topic_name},
                }
            },
        }
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ExecuteChangeSet of a change set held in CREATE_IN_PROGRESS is refused with
    InvalidChangeSetStatus naming its ARN and status and leaves the stack REVIEW_IN_PROGRESS; once
    the change set reaches CREATE_COMPLETE the same call succeeds and creates the topic."""
    cfn = ctx.client("cloudformation")
    macro_stack = ctx.unique_name("sim2real-cfn-execinvalid-macro-")
    macro_name = ctx.unique_name("sim2real-execinvalid-hold-")
    stack_name = ctx.unique_name("sim2real-cfn-execinvalid-")
    cs_name = ctx.unique_name("sim2real-cs-")
    topic_name = ctx.unique_name("sim2real-cfn-execinvalid-topic-")

    ctx.on_cleanup(lambda: _delete_stack(cfn, macro_stack))
    cfn.create_stack(
        StackName=macro_stack,
        TemplateBody=_macro_template(macro_name),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    _wait_stack_status(cfn, macro_stack, "CREATE_COMPLETE", timeout_s=600.0)

    ctx.on_cleanup(lambda: _cleanup(cfn, stack_name, cs_name))
    cs_arn = cfn.create_change_set(
        StackName=stack_name,
        ChangeSetName=cs_name,
        ChangeSetType="CREATE",
        TemplateBody=_template(topic_name, macro_name),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Id"]

    # Hold: the change set sits in CREATE_IN_PROGRESS while the macro sleeps.
    _wait_change_set_status(cfn, cs_name, stack_name, "CREATE_IN_PROGRESS", timeout_s=60.0,
                            interval_s=1.0)

    # Break: execute while the change set is held short of CREATE_COMPLETE.
    code, message = _error(
        lambda: cfn.execute_change_set(ChangeSetName=cs_name, StackName=stack_name)
    )
    # Real AWS returns the wire error code "InvalidChangeSetStatus" (no "Exception" suffix) --
    # distinct from the modeled botocore exception class name InvalidChangeSetStatusException.
    assert code == "InvalidChangeSetStatus", (
        f"expected InvalidChangeSetStatus, got {code}"
    )
    expected = (
        f"ChangeSet [{cs_arn}] cannot be executed in its current status of "
        f"[CREATE_IN_PROGRESS]"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # The window was still held when the call was refused.
    held = cfn.describe_change_set(ChangeSetName=cs_name, StackName=stack_name)["Status"]
    assert held == "CREATE_IN_PROGRESS", (
        f"the change set left the held window before the refusal was graded; got {held}"
    )

    # Effect absent, via an independent read: a rejected ExecuteChangeSet must not have
    # started creating anything. A stack from a CREATE-type change set sits in
    # REVIEW_IN_PROGRESS until an ExecuteChangeSet actually succeeds.
    review_status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert review_status == "REVIEW_IN_PROGRESS", (
        f"a rejected ExecuteChangeSet must not touch the stack; expected "
        f"REVIEW_IN_PROGRESS, got {review_status}"
    )

    # Restore: wait for the change set to reach the terminal state it was always heading to.
    # (raises with expected-vs-actual if it doesn't -- see _wait_change_set_status)
    _wait_change_set_status(cfn, cs_name, stack_name, "CREATE_COMPLETE",
                            timeout_s=_MACRO_HOLD_S + 180.0)

    # The identical call now succeeds -- and stays succeeded (see _wait_stack_status).
    cfn.execute_change_set(ChangeSetName=cs_name, StackName=stack_name)
    _wait_stack_status(cfn, stack_name, "CREATE_COMPLETE")

    # Terminal read, independent of the mutating call: the resource the change set
    # described actually exists.
    resources = cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    topic_resources = [r for r in resources if r["LogicalResourceId"] == "Topic"]
    assert topic_resources, f"expected a Topic resource on the stack, got {resources}"
    assert topic_resources[0]["ResourceStatus"] == "CREATE_COMPLETE", topic_resources[0]


def _error(fn):
    """Return (code, message) of the ClientError ``fn`` raises; raise if it succeeds."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _wait_change_set_status(cfn, cs_name, stack_name, target, timeout_s=120.0, interval_s=3.0):
    """Poll DescribeChangeSet until Status == target; raise (never silently return the
    last value) if the deadline passes first."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_change_set(ChangeSetName=cs_name, StackName=stack_name)["Status"]
        if status == target:
            return status
        time.sleep(interval_s)
    raise AssertionError(
        f"change set {cs_name} did not reach {target} within {timeout_s}s; last={status!r}"
    )


def _wait_stack_status(cfn, stack_name, target, timeout_s=180.0, interval_s=5.0):
    """Poll DescribeStacks until StackStatus == target; raise on timeout or on any other
    terminal status."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status == target:
            return status
        if not status.endswith("IN_PROGRESS"):
            raise AssertionError(f"stack {stack_name} reached {status}, expected {target}")
        time.sleep(interval_s)
    raise AssertionError(
        f"stack {stack_name} did not reach {target} within {timeout_s}s; last={status!r}"
    )


def _wait_change_set_terminal(cfn, cs_name, stack_name, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_change_set(ChangeSetName=cs_name, StackName=stack_name)[
                "Status"
            ]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] in ("ChangeSetNotFound",) or
                (exc.response["Error"]["Code"] == "ValidationError"
                 and "does not exist" in exc.response["Error"].get("Message", ""))
            ):
                raise
            return None
        if status in ("CREATE_COMPLETE", "FAILED", "DELETE_COMPLETE"):
            return status
        time.sleep(interval_s)
    return status


def _wait_stack_terminal(cfn, stack_name, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return
        if not status.endswith("IN_PROGRESS"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not settle within {timeout_s}s")


def _delete_stack(cfn, stack_name):
    """Delete the stack and wait for it to be gone; a stack that never existed is fine."""
    from botocore.exceptions import ClientError

    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise
        return
    status = _wait_stack_terminal(cfn, stack_name, timeout_s=600)
    if status not in (None, "DELETE_COMPLETE"):
        raise AssertionError(f"stack {stack_name} did not delete; last={status!r}")


def _cleanup(cfn, stack_name, cs_name):
    _wait_change_set_terminal(cfn, cs_name, stack_name, timeout_s=_MACRO_HOLD_S + 180)
    try:
        cfn.delete_change_set(ChangeSetName=cs_name, StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] in ("ChangeSetNotFound",) or
            (exc.response["Error"]["Code"] == "ValidationError"
             and "does not exist" in exc.response["Error"].get("Message", ""))
        ):
            raise
    _delete_stack(cfn, stack_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
