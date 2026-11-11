"""deploy-firewall-rule-group-cfn-enforced-blocking."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-firewall-rule-group-cfn-enforced-blocking"
GROUP = "state-machine"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """A CFN-deployed FirewallDomainList+FirewallRuleGroup(+FirewallRule) is proven
    functional (not just CREATE_COMPLETE) by associating it to a VPC and observing a
    COMPLETE association status with the rule correctly listed."""
    r53r = ctx.client("route53resolver")
    vpc_id = _create_vpc(ctx)

    domain_list_name = ctx.unique_name("sim2real-r53r-dl-")
    rule_group_name = ctx.unique_name("sim2real-r53r-rg-")
    blocked_domain = f"blocked.{ctx.unique_name('sim2real-')}.test"
    resource_tags = [{"Key": "sim2real", "Value": "true"}]

    template = json.dumps(
        {
            "Resources": {
                "DomainList": {
                    "Type": "AWS::Route53Resolver::FirewallDomainList",
                    "Properties": {
                        "Name": domain_list_name,
                        "Domains": [blocked_domain],
                        "Tags": resource_tags,
                    },
                },
                "RuleGroup": {
                    "Type": "AWS::Route53Resolver::FirewallRuleGroup",
                    "Properties": {
                        "Name": rule_group_name,
                        "FirewallRules": [
                            {
                                "FirewallDomainListId": {"Ref": "DomainList"},
                                "Priority": 10,
                                "Action": "BLOCK",
                                "BlockResponse": "NODATA",
                            }
                        ],
                        "Tags": resource_tags,
                    },
                },
            },
            "Outputs": {
                "DomainListId": {"Value": {"Ref": "DomainList"}},
                "RuleGroupId": {"Value": {"Ref": "RuleGroup"}},
            },
        }
    )

    stack_name, outputs = _deploy_cfn(ctx, template)
    _register_stack_cleanup(ctx, stack_name)

    domain_list_id = outputs["DomainListId"]
    rule_group_id = outputs["RuleGroupId"]

    # Confirm the rule was actually created (not a placeholder) and references the domain list.
    rules = r53r.list_firewall_rules(FirewallRuleGroupId=rule_group_id)["FirewallRules"]
    assert len(rules) == 1, f"expected exactly 1 rule in the CFN-deployed group, got {rules}"
    assert rules[0]["Action"] == "BLOCK", f"expected Action=BLOCK, got {rules[0]['Action']}"
    assert rules[0]["FirewallDomainListId"] == domain_list_id, (
        f"rule references domain list {rules[0]['FirewallDomainListId']!r}, "
        f"expected {domain_list_id!r}"
    )

    # Prove the group is a live, associable resource: associate it to a freshly created VPC.
    assoc_name = ctx.unique_name("sim2real-r53r-assoc-")
    assoc = r53r.associate_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        FirewallRuleGroupId=rule_group_id,
        VpcId=vpc_id,
        Priority=101,
        Name=assoc_name,
        MutationProtection="DISABLED",
        Tags=resource_tags,
    )["FirewallRuleGroupAssociation"]
    assoc_id = assoc["Id"]

    # Disassociate before the stack is torn down (rule group can't delete while associated).
    def _disassociate() -> None:
        try:
            r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=assoc_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        _poll_until(
            lambda: _get_assoc_or_none(ctx, assoc_id),
            lambda v: v is None,
            timeout_s=90.0,
            interval_s=2.0,
        )

    ctx.on_cleanup(_disassociate)

    final = _poll_until(
        lambda: r53r.get_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=assoc_id
        )["FirewallRuleGroupAssociation"],
        lambda a: a["Status"] == "COMPLETE",
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert final["Status"] == "COMPLETE", f"expected COMPLETE, got {final['Status']}"
    assert final["FirewallRuleGroupId"] == rule_group_id, (
        f"association references rule group {final['FirewallRuleGroupId']!r}, "
        f"expected {rule_group_id!r}"
    )
    assert final["VpcId"] == vpc_id, f"association bound to {final['VpcId']!r}, expected {vpc_id!r}"

    # And the rule listing is still consistent post-association.
    rules_after = r53r.list_firewall_rules(FirewallRuleGroupId=rule_group_id)["FirewallRules"]
    assert len(rules_after) == 1, f"expected exactly 1 rule after association, got {rules_after}"
    assert rules_after[0]["FirewallDomainListId"] == domain_list_id, (
        f"post-association rule references domain list {rules_after[0]['FirewallDomainListId']!r}, "
        f"expected {domain_list_id!r}"
    )


# ===== helpers =====


def _create_vpc(ctx: Any) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-r53r-vpc-")
    resp = ec2.create_vpc(
        CidrBlock="10.91.0.0/16",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
            }
        ],
    )
    vpc_id = resp["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return vpc_id


def _deploy_cfn(ctx: Any, template_body: str) -> tuple[str, dict[str, str]]:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-r53r-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_IAM"],
    )
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}
    return stack_name, outputs


def _register_stack_cleanup(ctx: Any, stack_name: str) -> None:
    def _delete() -> None:
        cfn = ctx.client("cloudformation")
        cfn.delete_stack(StackName=stack_name)
        waiter = cfn.get_waiter("stack_delete_complete")
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    ctx.on_cleanup(_delete)


def _get_assoc_or_none(ctx: Any, assoc_id: str) -> dict | None:
    from botocore.exceptions import ClientError

    r53r = ctx.client("route53resolver")
    try:
        return r53r.get_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=assoc_id
        )["FirewallRuleGroupAssociation"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
