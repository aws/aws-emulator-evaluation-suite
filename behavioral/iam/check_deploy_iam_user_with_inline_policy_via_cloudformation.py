"""deploy-iam-user-with-inline-policy-via-cloudformation."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-iam-user-with-inline-policy-via-cloudformation"
GROUP = "deploy"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed AWS::IAM::User with an inline Policies property produces
    a retrievable inline policy document, and stack deletion cascades to
    remove both the inline policy and the user itself."""
    iam = ctx.client("iam")
    cfn = ctx.client("cloudformation")
    user_name = ctx.unique_name("sim2real-behav-user-")
    inline_policy_name = ctx.unique_name("sim2real-behav-inline-")
    stack_name = ctx.unique_name("sim2real-behav-stack-")

    template = {
        "Resources": {
            "TestUser": {
                "Type": "AWS::IAM::User",
                "Properties": {
                    "UserName": user_name,
                    "Policies": [
                        {
                            "PolicyName": inline_policy_name,
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "dynamodb:GetItem",
                                        "Resource": "arn:aws:dynamodb:*:*:table/sim2real-behav-example-table",
                                    }
                                ],
                            },
                        }
                    ],
                },
            }
        },
        "Outputs": {"UserArn": {"Value": {"Fn::GetAtt": ["TestUser", "Arn"]}}},
    }
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name))
    stack = _wait_stack_status(ctx, stack_name, {"CREATE_COMPLETE"})
    outputs = _stack_outputs(stack)

    user = iam.get_user(UserName=user_name)["User"]
    assert user["Arn"] == outputs["UserArn"], (
        f"expected get_user Arn to match stack output UserArn, got {user['Arn']!r} vs {outputs['UserArn']!r}"
    )

    inline = iam.get_user_policy(UserName=user_name, PolicyName=inline_policy_name)
    statement = inline["PolicyDocument"]["Statement"][0]
    assert statement["Effect"] == "Allow", f"expected Effect Allow, got {statement['Effect']!r}"
    assert statement["Action"] == "dynamodb:GetItem", (
        f"expected Action dynamodb:GetItem, got {statement['Action']!r}"
    )
    assert statement["Resource"] == "arn:aws:dynamodb:*:*:table/sim2real-behav-example-table", (
        f"expected Resource arn:aws:dynamodb:*:*:table/sim2real-behav-example-table, got {statement['Resource']!r}"
    )

    _delete_stack_and_wait(ctx, stack_name)
    # Stack deletion cascades: both the inline policy and the user itself are gone.
    inline_policy_code, inline_policy_code_msg = _client_error(
        lambda: iam.get_user_policy(UserName=user_name, PolicyName=inline_policy_name)
    )
    assert inline_policy_code == "NoSuchEntity", (
        f"expected NoSuchEntity for inline policy after stack delete, got {inline_policy_code!r}"
    )
    assert inline_policy_code_msg == f"The user with name {user_name} cannot be found.", f"unexpected error message {inline_policy_code_msg!r}"
    user_code, user_code_msg = _client_error(lambda: iam.get_user(UserName=user_name))
    assert user_code == "NoSuchEntity", f"expected NoSuchEntity for user after stack delete, got {user_code!r}"
    assert user_code_msg == f"The user with name {user_name} cannot be found.", f"unexpected error message {user_code_msg!r}"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _wait_stack_status(ctx, stack_name, ok_statuses, timeout_s=600.0, interval_s=5.0):
    cfn = ctx.client("cloudformation")
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


def _wait_stack_deleted(ctx, stack_name, timeout_s=600.0, interval_s=5.0):
    cfn = ctx.client("cloudformation")
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


def _delete_stack_and_wait(ctx, stack_name):
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    _wait_stack_deleted(ctx, stack_name)


def _stack_outputs(stack):
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
