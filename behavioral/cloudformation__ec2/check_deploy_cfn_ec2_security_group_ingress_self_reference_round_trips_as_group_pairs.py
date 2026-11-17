"""deploy-cfn-ec2-security-group-ingress-self-reference-round-trips-as-group-pairs."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-ec2-security-group-ingress-self-reference-round-trips-as-group-pairs"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

_VPC_CIDR = "10.113.0.0/16"
_TERMINAL = frozenset(
    {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
    }
)


def _template(tag_value: str) -> str:
    """A VPC, one security group and three standalone ingress rules each sourced from that group."""
    tags_ = [{"Key": "sim2real-check", "Value": tag_value}]
    group_ref = {"Fn::GetAtt": ["ClusterGroup", "GroupId"]}
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Vpc": {
                    "Type": "AWS::EC2::VPC",
                    "Properties": {"CidrBlock": _VPC_CIDR, "Tags": tags_},
                },
                "ClusterGroup": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {
                        "GroupDescription": "sim2real self-reference ingress",
                        "VpcId": {"Ref": "Vpc"},
                        "Tags": tags_,
                    },
                },
                "SelfTcp988": {
                    "Type": "AWS::EC2::SecurityGroupIngress",
                    "Properties": {
                        "GroupId": group_ref,
                        "IpProtocol": "tcp",
                        "FromPort": 988,
                        "ToPort": 988,
                        "SourceSecurityGroupId": group_ref,
                    },
                },
                "SelfTcpRange": {
                    "Type": "AWS::EC2::SecurityGroupIngress",
                    "Properties": {
                        "GroupId": group_ref,
                        "IpProtocol": "tcp",
                        "FromPort": 1018,
                        "ToPort": 1023,
                        "SourceSecurityGroupId": group_ref,
                    },
                },
                "SelfAll": {
                    "Type": "AWS::EC2::SecurityGroupIngress",
                    "Properties": {
                        "GroupId": group_ref,
                        "IpProtocol": "-1",
                        "SourceSecurityGroupId": group_ref,
                    },
                },
            },
            "Outputs": {
                "GroupId": {"Value": group_ref},
                "RuleId988": {"Value": {"Ref": "SelfTcp988"}},
                "RuleIdRange": {"Value": {"Ref": "SelfTcpRange"}},
                "RuleIdAll": {"Value": {"Ref": "SelfAll"}},
            },
        }
    )


def _wait_terminal(cfn, stack_id: str, timeout_s: float = 240.0) -> str:
    """Poll DescribeStacks by StackId until a terminal status; return it."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in _TERMINAL:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(3)


def _delete_stack(cfn, stack_id: str) -> None:
    """DeleteStack, then poll by StackId to DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + 240.0
    while True:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED" or time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} delete ended {status!r}")
        time.sleep(3)


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Standalone AWS::EC2::SecurityGroupIngress resources whose SourceSecurityGroupId is the
    same group reach CREATE_COMPLETE; DescribeSecurityGroups and DescribeSecurityGroupRules
    each list one rule per resource, with the group itself as the referenced source."""
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")

    stack_name = ctx.unique_name("sim2real-sgselfref-")
    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(CHECK),
        Tags=[{"Key": "sim2real", "Value": stack_name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))

    status = _wait_terminal(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack_name!r} ended {status!r}, expected CREATE_COMPLETE"
    )

    stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack["Outputs"]}
    group = outputs["GroupId"]

    sg = ec2.describe_security_groups(GroupIds=[group])["SecurityGroups"][0]
    ingress = sorted(
        (
            p["IpProtocol"],
            p.get("FromPort"),
            p.get("ToPort"),
            tuple(sorted(g["GroupId"] for g in p["UserIdGroupPairs"])),
        )
        for p in sg["IpPermissions"]
    )
    want = sorted(
        [
            ("tcp", 988, 988, (group,)),
            ("tcp", 1018, 1023, (group,)),
            ("-1", None, None, (group,)),
        ]
    )
    assert ingress == want, (
        f"DescribeSecurityGroups IpPermissions: expected {want!r}, got {ingress!r}"
    )

    rules = []
    for page in ec2.get_paginator("describe_security_group_rules").paginate(
        Filters=[{"Name": "group-id", "Values": [group]}]
    ):
        rules.extend(page["SecurityGroupRules"])
    inbound = [r for r in rules if not r["IsEgress"]]
    assert len(inbound) == 3, (
        f"DescribeSecurityGroupRules lists {len(inbound)} ingress rules: {inbound!r}"
    )
    bad = [r for r in inbound if r.get("ReferencedGroupInfo", {}).get("GroupId") != group]
    assert bad == [], f"an ingress rule does not reference the group itself: {bad!r}"

    rule_ids = sorted(r["SecurityGroupRuleId"] for r in inbound)
    want_ids = sorted([outputs["RuleId988"], outputs["RuleIdRange"], outputs["RuleIdAll"]])
    assert rule_ids == want_ids, (
        f"DescribeSecurityGroupRules ids {rule_ids!r} do not match the three resources' Ref "
        f"values {want_ids!r} one-to-one"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
