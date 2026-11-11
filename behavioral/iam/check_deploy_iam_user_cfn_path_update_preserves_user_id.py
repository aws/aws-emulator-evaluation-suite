"""deploy-iam-user-cfn-path-update-preserves-user-id."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-iam-user-cfn-path-update-preserves-user-id"
GROUP = "deploy"
SERVICES = ["iam"]


def _template(user_name: str, path: str) -> str:
    return json.dumps(
        {
            "Resources": {
                "TestUser": {
                    "Type": "AWS::IAM::User",
                    "Properties": {"UserName": user_name, "Path": path},
                }
            },
            "Outputs": {
                "UserRef": {"Value": {"Ref": "TestUser"}},
                "UserArn": {"Value": {"Fn::GetAtt": ["TestUser", "Arn"]}},
            },
        }
    )


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN AWS::IAM::User's Path shows in GetAtt Arn and GetUser; since Path is not create-only,
    a stack update changing it keeps the same UserId (updated in place, not replaced)."""
    iam = ctx.client("iam")
    cfn = ctx.client("cloudformation")
    user_name = ctx.unique_name("sim2real-behav-user-")
    stack_name = ctx.unique_name("sim2real-behav-stack-")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(user_name, "/initial/"),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_name))
    stack = _wait_terminal(cfn, stack_name, {"CREATE_COMPLETE"})
    assert stack["StackStatus"] == "CREATE_COMPLETE", f"create ended in {stack['StackStatus']!r}"
    outputs = _outputs(stack)
    assert outputs["UserRef"] == user_name, f"expected Ref to be {user_name!r}, got {outputs['UserRef']!r}"

    user = iam.get_user(UserName=user_name)["User"]
    assert user["Path"] == "/initial/", f"expected Path '/initial/', got {user['Path']!r}"
    assert user["Arn"] == outputs["UserArn"], (
        f"expected GetAtt Arn {outputs['UserArn']!r} to match GetUser's {user['Arn']!r}"
    )
    assert user["Arn"].endswith(f":user/initial/{user_name}"), (
        f"expected the Arn to carry the Path segment, got {user['Arn']!r}"
    )
    user_id = user["UserId"]
    assert user_id.startswith("AIDA"), f"expected a UserId starting with AIDA, got {user_id!r}"

    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=_template(user_name, "/updated/"),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    stack = _wait_terminal(cfn, stack_name, {"UPDATE_COMPLETE"})
    assert stack["StackStatus"] == "UPDATE_COMPLETE", f"update ended in {stack['StackStatus']!r}"

    updated = iam.get_user(UserName=user_name)["User"]
    assert updated["Path"] == "/updated/", f"expected Path '/updated/', got {updated['Path']!r}"
    assert updated["UserId"] == user_id, (
        "Path is not create-only, so the update must mutate the SAME user in place: "
        f"UserId changed from {user_id!r} to {updated['UserId']!r}"
    )

    _delete_stack_and_wait(cfn, stack_name)
    code, message = _error(lambda: iam.get_user(UserName=user_name))
    assert code == "NoSuchEntity", f"expected NoSuchEntity after stack delete, got {code!r}"
    expected = f"The user with name {user_name} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected NoSuchEntity, but the call SUCCEEDED and returned {result!r}")


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


def _outputs(stack):
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
