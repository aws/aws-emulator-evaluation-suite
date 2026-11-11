"""deploy-cfn-public-resource-policy-rejected-by-block-public-policy-and-rolled-back."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-public-resource-policy-rejected-by-block-public-policy-and-rolled-back"
GROUP = "deploy"
SERVICES = ["secretsmanager"]

_DEPLOY_TIMEOUT_S = 300.0


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A ResourcePolicy with BlockPublicPolicy and a wildcard-principal Allow fails the deploy: the
    stack rolls back and its secret is gone; the same template narrowed by aws:PrincipalAccount
    deploys, and the secret carries that policy.
    """
    sm = ctx.client("secretsmanager")
    cfn = ctx.client("cloudformation")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    statement = {
        "Effect": "Allow",
        "Principal": "*",
        "Action": "secretsmanager:GetSecretValue",
        "Resource": "*",
    }

    def template(name, stmt):
        return json.dumps(
            {
                "AWSTemplateFormatVersion": "2010-09-09",
                "Resources": {
                    "Guarded": {
                        "Type": "AWS::SecretsManager::Secret",
                        "Properties": {
                            "Name": name,
                            "SecretString": "guarded-value",
                            "Tags": [{"Key": "sim2real", "Value": CHECK}],
                        },
                    },
                    "GuardedPolicy": {
                        "Type": "AWS::SecretsManager::ResourcePolicy",
                        "Properties": {
                            "SecretId": {"Ref": "Guarded"},
                            "BlockPublicPolicy": True,
                            "ResourcePolicy": {"Version": "2012-10-17", "Statement": [stmt]},
                        },
                    },
                },
            }
        )

    public_name = ctx.unique_name("sim2real-behav-cfnpublic-")
    public_stack = ctx.unique_name("sim2real-behav-cfnpublic-")
    ctx.on_cleanup(lambda: _delete_stack(cfn, public_stack))
    cfn.create_stack(StackName=public_stack, TemplateBody=template(public_name, statement))
    status = _wait_stack(cfn, public_stack)
    assert status == "ROLLBACK_COMPLETE", f"a public policy under BlockPublicPolicy must roll back; it ended {status!r}"
    failed = [f for f in _failures(cfn, public_stack) if f[0] == "GuardedPolicy"]
    assert [f[:2] for f in failed] == [("GuardedPolicy", "CREATE_FAILED")], f"failures were {failed!r}"
    # The reason wraps the service's refusal in handler diagnostics that carry per-request ids; the
    # service's own sentence is graded exactly and the diagnostics only for the status they report.
    reason, _, diagnostics = (failed[0][2] or "").partition(" (Service: SecretsManager, ")
    assert reason == (
        'Resource handler returned message: "You can not attach a resource policy that grants '
        'Public access to your secret.'
    ), f"unexpected failure reason: {failed[0][2]!r}"
    assert diagnostics.startswith("Status Code: 400,"), f"unexpected diagnostics: {diagnostics!r}"
    code, message = _describe(sm, public_name)
    assert code == "ResourceNotFoundException", (
        f"the rolled-back secret {public_name!r} must be gone; DescribeSecret gave {code!r}"
    )
    assert message == "Secrets Manager can't find the specified secret.", f"unexpected message: {message!r}"

    scoped = {**statement, "Condition": {"StringEquals": {"aws:PrincipalAccount": account_id}}}
    scoped_name = ctx.unique_name("sim2real-behav-cfnscoped-")
    scoped_stack = ctx.unique_name("sim2real-behav-cfnscoped-")
    ctx.on_cleanup(lambda: _delete_stack(cfn, scoped_stack))
    cfn.create_stack(StackName=scoped_stack, TemplateBody=template(scoped_name, scoped))
    status = _wait_stack(cfn, scoped_stack)
    assert status == "CREATE_COMPLETE", (
        f"the account-scoped control must deploy; it ended {status!r}: {_failures(cfn, scoped_stack)!r}"
    )
    attached = json.loads(sm.get_resource_policy(SecretId=scoped_name)["ResourcePolicy"])
    assert attached["Statement"][0].get("Condition") == scoped["Condition"], (
        f"the deployed secret must carry the account-scoped policy; got {attached!r}"
    )


def _wait_stack(cfn, stack_name, timeout_s=_DEPLOY_TIMEOUT_S, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if not status.endswith("_IN_PROGRESS"):
            return status
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack_name} still {status} after {timeout_s}s")
        time.sleep(interval_s)


def _failures(cfn, stack_name):
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    return [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in events
        if e["ResourceStatus"].endswith("_FAILED")
    ]


def _describe(sm, name):
    try:
        sm.describe_secret(SecretId=name)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return "<exists>", None


def _delete_stack(cfn, stack_name, timeout_s=_DEPLOY_TIMEOUT_S):
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": int(timeout_s // 2)}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
