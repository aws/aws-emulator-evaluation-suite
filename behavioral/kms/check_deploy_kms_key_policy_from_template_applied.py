"""deploy-kms-key-policy-from-template-applied."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-kms-key-policy-from-template-applied"
GROUP = "server-side"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A key deployed via CloudFormation with an embedded custom key policy returns
    that exact policy from GetKeyPolicy -- not a synthesized default."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    stack_name = ctx.unique_name("sim2real-kms-pol-")
    marker_sid = ctx.unique_name("Sim2RealMarkerStatement").replace("-", "")

    key_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableRootPermissions",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": marker_sid,
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["kms:DescribeKey", "kms:GetKeyPolicy"],
                "Resource": "*",
            },
        ],
    }
    template = {
        "Resources": {
            "PolicyKey": {
                "Type": "AWS::KMS::Key",
                "Properties": {
                    "Description": "sim2real key-policy test key",
                    "KeyPolicy": key_policy,
                },
            }
        },
        "Outputs": {"KeyId": {"Value": {"Ref": "PolicyKey"}}},
    }

    outputs = _deploy_cfn(ctx, stack_name, template)
    key_id = outputs["KeyId"]

    kms = ctx.client("kms")
    policy_doc = json.loads(kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"])

    statements_by_sid = {s["Sid"]: s for s in policy_doc["Statement"] if "Sid" in s}
    assert len(policy_doc["Statement"]) == 2, (
        f"expected exactly the 2 statements from the template's KeyPolicy, got "
        f"{len(policy_doc['Statement'])}: {policy_doc}"
    )
    assert marker_sid in statements_by_sid, (
        f"custom marker statement {marker_sid!r} from the template's KeyPolicy is "
        f"missing from the live policy: {policy_doc}"
    )
    marker_statement = statements_by_sid[marker_sid]
    assert marker_statement["Effect"] == "Allow", (
        f"marker statement Effect: expected 'Allow', got {marker_statement['Effect']!r}"
    )
    assert set(marker_statement["Action"]) == {"kms:DescribeKey", "kms:GetKeyPolicy"}, (
        f"marker statement Action: expected "
        f"{{'kms:DescribeKey', 'kms:GetKeyPolicy'}}, got {marker_statement['Action']!r}"
    )

    root_statement = statements_by_sid["EnableRootPermissions"]
    assert root_statement["Effect"] == "Allow", (
        f"root statement Effect: expected 'Allow', got {root_statement['Effect']!r}"
    )
    assert root_statement["Action"] == "kms:*", (
        f"root statement Action: expected 'kms:*', got {root_statement['Action']!r}"
    )


def _deploy_cfn(ctx: Any, stack_name: str, template: dict) -> dict[str, str]:
    cfn = ctx.client("cloudformation")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Capabilities=["CAPABILITY_IAM"],
    )

    def _cleanup() -> None:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )

    ctx.on_cleanup(_cleanup)
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
