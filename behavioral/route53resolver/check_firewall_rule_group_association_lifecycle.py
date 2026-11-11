"""firewall-rule-group-association-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "firewall-rule-group-association-lifecycle"
GROUP = "state-machine"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateFirewallRuleGroup transitions the association to COMPLETE, it is then
    visible via Get/List, and DisassociateFirewallRuleGroup removes it from both."""
    r53r = ctx.client("route53resolver")
    vpc_id = _create_test_vpc(ctx)
    group_id = _create_rule_group(ctx, r53r)

    assoc = r53r.associate_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        FirewallRuleGroupId=group_id,
        VpcId=vpc_id,
        Priority=101,
        Name=ctx.unique_name("sim2real-frg-assoc-"),
    )["FirewallRuleGroupAssociation"]
    assoc_id = assoc["Id"]
    ctx.on_cleanup(lambda: _disassociate(r53r, assoc_id))

    status = _poll_assoc_status(r53r, assoc_id, {"COMPLETE"}, timeout_s=180.0)
    assert status == "COMPLETE", f"expected COMPLETE, got {status}"

    fetched = r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)[
        "FirewallRuleGroupAssociation"
    ]
    assert fetched["VpcId"] == vpc_id, f"expected VpcId {vpc_id}, got {fetched['VpcId']}"
    assert fetched["FirewallRuleGroupId"] == group_id, (
        f"expected FirewallRuleGroupId {group_id}, got {fetched['FirewallRuleGroupId']}"
    )

    listed = r53r.list_firewall_rule_group_associations(VpcId=vpc_id)["FirewallRuleGroupAssociations"]
    assert any(a["Id"] == assoc_id for a in listed), (
        f"association {assoc_id} missing from ListFirewallRuleGroupAssociations({vpc_id})"
    )

    r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=assoc_id)
    removed = _poll_until_removed(r53r, assoc_id, timeout_s=180.0)
    assert removed, "association was never removed after DisassociateFirewallRuleGroup"

    listed_after = r53r.list_firewall_rule_group_associations(VpcId=vpc_id)["FirewallRuleGroupAssociations"]
    assert not any(a["Id"] == assoc_id for a in listed_after), (
        f"disassociated association {assoc_id} still present in ListFirewallRuleGroupAssociations({vpc_id})"
    )


def _create_test_vpc(ctx) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-r53r-vpc-")
    vpc = ec2.create_vpc(
        CidrBlock="10.91.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return vpc_id


def _create_rule_group(ctx, r53r) -> str:
    group_id = r53r.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        Name=ctx.unique_name("sim2real-frg-"),
    )["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(lambda: _delete_rule_group(r53r, group_id))
    return group_id


def _delete_rule_group(r53r, group_id: str) -> None:
    try:
        r53r.delete_firewall_rule_group(FirewallRuleGroupId=group_id)
    except r53r.exceptions.ResourceNotFoundException:
        pass


def _disassociate(r53r, assoc_id: str) -> None:
    try:
        r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=assoc_id)
    except r53r.exceptions.ResourceNotFoundException:
        pass


def _poll_assoc_status(r53r, assoc_id: str, terminal_statuses, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)[
            "FirewallRuleGroupAssociation"
        ]["Status"]
        if status in terminal_statuses:
            return status
        time.sleep(interval_s)
    return status


def _poll_until_removed(r53r, assoc_id: str, timeout_s=120.0, interval_s=3.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)
        except r53r.exceptions.ResourceNotFoundException:
            return True
        time.sleep(interval_s)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
