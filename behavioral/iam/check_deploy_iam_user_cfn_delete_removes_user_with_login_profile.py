"""deploy-iam-user-cfn-delete-removes-user-with-login-profile."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-iam-user-cfn-delete-removes-user-with-login-profile"
GROUP = "deploy"
SERVICES = ["iam"]


def _template(user_name: str) -> str:
    return json.dumps(
        {
            "Resources": {
                "TestUser": {"Type": "AWS::IAM::User", "Properties": {"UserName": user_name}}
            }
        }
    )


@tags(
    "axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control"
)
def run(ctx) -> None:
    """An out-of-band login profile on a CFN-managed IAM user blocks DeleteUser and DeleteStack
    alike: the stack ends DELETE_FAILED with the user intact; after removing the profile, the
    same DeleteStack succeeds and the user is gone."""
    iam = ctx.client("iam")
    cfn = ctx.client("cloudformation")
    user_name = ctx.unique_name("sim2real-behav-user-")
    stack_name = ctx.unique_name("sim2real-behav-stack-")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(user_name),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_name))
    stack = _wait_terminal(cfn, stack_name, {"CREATE_COMPLETE"})
    assert stack["StackStatus"] == "CREATE_COMPLETE", f"create ended in {stack['StackStatus']!r}"

    iam.create_login_profile(UserName=user_name, Password="Sim2real-Test-P4ssword!")
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: iam.delete_login_profile(UserName=user_name)))

    # Precondition: a bare DeleteUser is refused while the login profile exists.
    code, message = _error(lambda: iam.delete_user(UserName=user_name))
    assert code == "DeleteConflict", (
        f"expected a bare DeleteUser to be refused by the attached login profile with "
        f"DeleteConflict, got {code!r}"
    )
    expected = "Cannot delete entity, must delete login profile first."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    iam.get_login_profile(UserName=user_name)  # still present

    cfn.delete_stack(StackName=stack_name)
    stack = _wait_delete_terminal(cfn, stack_name)
    assert stack["StackStatus"] == "DELETE_FAILED", (
        "CloudFormation's own delete handler hits the same DeleteConflict a bare DeleteUser "
        f"does, so the stack must end DELETE_FAILED, got {stack['StackStatus']!r}"
    )
    reason = _resource_status_reason(cfn, stack_name, "TestUser", "DELETE_FAILED")
    assert reason is not None and "login profile" in reason.lower(), (
        f"expected the DELETE_FAILED reason to name the login profile conflict, got {reason!r}"
    )
    still_there = iam.get_user(UserName=user_name)["User"]
    assert still_there["UserName"] == user_name, (
        f"a DELETE_FAILED stack must leave the user in place, got {still_there!r}"
    )

    # Positive control: once the dependent is cleared out of band, the SAME delete succeeds.
    iam.delete_login_profile(UserName=user_name)
    cfn.delete_stack(StackName=stack_name)
    stack = _wait_delete_terminal(cfn, stack_name)
    assert stack["StackStatus"] == "DELETE_COMPLETE", (
        f"expected the retried delete to succeed once the login profile is gone, got {stack['StackStatus']!r}"
    )
    user_code, user_message = _error(lambda: iam.get_user(UserName=user_name))
    assert user_code == "NoSuchEntity", f"expected NoSuchEntity after the retried delete, got {user_code!r}"
    expected = f"The user with name {user_name} cannot be found."
    assert user_message == expected, f"expected message {expected!r}, got {user_message!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _resource_status_reason(cfn, stack_name, logical_id, status):
    for event in cfn.describe_stack_events(StackName=stack_name)["StackEvents"]:
        if event.get("LogicalResourceId") == logical_id and event.get("ResourceStatus") == status:
            return event.get("ResourceStatusReason")
    return None


def _wait_delete_terminal(cfn, stack_name, timeout_s=300.0, interval_s=5.0):
    """Poll DescribeStacks until DELETE_COMPLETE or DELETE_FAILED.

    DescribeStacks by name stops showing a DELETE_COMPLETE stack, so "does not exist" is success.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            if "does not exist" in str(exc):
                return {"StackStatus": "DELETE_COMPLETE"}
            raise
        status = stacks[0]["StackStatus"]
        if status in {"DELETE_COMPLETE", "DELETE_FAILED"}:
            return stacks[0]
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach a delete terminal within {timeout_s}s")


def _wait_terminal(cfn, stack_name, ok_statuses, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        status = stacks[0]["StackStatus"]
        if status in ok_statuses:
            return stacks[0]
        if status.endswith("FAILED") or status == "ROLLBACK_COMPLETE":
            raise AssertionError(f"stack {stack_name} entered unexpected status {status}")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach {ok_statuses} within {timeout_s}s")


def _delete_stack_and_wait(cfn, stack_name, timeout_s=300.0, interval_s=5.0):
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            if "does not exist" in str(exc):
                return
            raise
        status = stacks[0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} entered DELETE_FAILED")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} was not deleted within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
