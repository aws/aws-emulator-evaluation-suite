"""deploy-iam-role-cloudformation-malformed-trust-policy-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "deploy-iam-role-cloudformation-malformed-trust-policy-rejected"
GROUP = "deploy"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CFN AWS::IAM::Role whose trust policy statement lacks Effect fails to create and the role
    is never persisted, while an otherwise-identical stack with a valid trust policy deploys."""
    iam = ctx.client("iam")
    cfn = ctx.client("cloudformation")

    bad_stack_name = ctx.unique_name("sim2real-cfnbadrole-")
    bad_role_name = f"{bad_stack_name}-role"
    bad_trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                # Missing required "Effect" field -> MalformedPolicyDocumentException
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": ["sts:AssumeRole"],
            }
        ],
    }
    bad_template = json.dumps(
        {
            "Resources": {
                "TestRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": bad_role_name,
                        "AssumeRolePolicyDocument": bad_trust_policy,
                    },
                }
            }
        }
    )

    cfn.create_stack(
        StackName=bad_stack_name,
        TemplateBody=bad_template,
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, bad_stack_name))

    final_status = _wait_for_stack_terminal(ctx, bad_stack_name, timeout_s=180)
    assert final_status in ("ROLLBACK_COMPLETE", "CREATE_FAILED"), (
        f"expected ROLLBACK_COMPLETE or CREATE_FAILED for a malformed trust "
        f"policy, got {final_status!r}"
    )

    # The CFN resource handler wraps IAM's rejection rather than surfacing IAM's
    # own error code: it names the missing field directly and attributes the
    # failure to the IAM service.
    reason = _role_failure_reason(ctx, bad_stack_name)
    # message varies: the reason embeds the per-call IAM Request ID, the SDK attempt count and the
    # CloudFormation RequestToken, so only its stable fragments are graded.
    assert reason and "Missing required field Effect" in reason and "Iam" in reason, (
        f"expected the TestRole resource's failure reason to name the missing "
        f"Effect field and attribute it to Iam, got {reason!r}"
    )

    code, code_msg = _client_error(lambda: iam.get_role(RoleName=bad_role_name))
    assert code == "NoSuchEntity", (
        f"role must not be persisted after a rejected create, got code={code!r}"
    )
    assert code_msg == f"The role with name {bad_role_name} cannot be found.", f"unexpected error message {code_msg!r}"

    # Positive control: an otherwise-identical stack with a syntactically valid
    # trust policy deploys successfully and the role is retrievable.
    good_stack_name = ctx.unique_name("sim2real-cfngoodrole-")
    good_role_name = f"{good_stack_name}-role"
    good_trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": ["sts:AssumeRole"],
            }
        ],
    }
    good_template = json.dumps(
        {
            "Resources": {
                "TestRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": good_role_name,
                        "AssumeRolePolicyDocument": good_trust_policy,
                    },
                }
            }
        }
    )
    _deploy_cfn(ctx, good_stack_name, good_template, capabilities=["CAPABILITY_NAMED_IAM"])
    role = iam.get_role(RoleName=good_role_name)["Role"]
    assert role["RoleName"] == good_role_name, (
        f"expected the positive-control role {good_role_name!r} to be "
        f"retrievable after a successful deploy, got {role['RoleName']!r}"
    )


def _deploy_cfn(ctx, stack_name, template_body, capabilities=None):
    cfn = ctx.client("cloudformation")
    kwargs = {
        "StackName": stack_name,
        "TemplateBody": template_body,
        "Tags": [{"Key": "sim2real", "Value": CHECK}],
    }
    if capabilities:
        kwargs["Capabilities"] = capabilities
    cfn.create_stack(**kwargs)
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


def _role_failure_reason(ctx, stack_name):
    cfn = ctx.client("cloudformation")
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    for event in events:
        if event.get("LogicalResourceId") == "TestRole" and event.get("ResourceStatus") == (
            "CREATE_FAILED"
        ):
            return event.get("ResourceStatusReason", "")
    return ""


def _delete_stack(ctx, stack_name):
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    waiter = cfn.get_waiter("stack_delete_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


def _wait_for_stack_terminal(ctx, stack_name, timeout_s=180.0, interval_s=5.0):
    import time

    cfn = ctx.client("cloudformation")
    terminal = {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
    }
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        status = stacks[0]["StackStatus"]
        if status in terminal:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} never reached a terminal status (last={status})")


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
