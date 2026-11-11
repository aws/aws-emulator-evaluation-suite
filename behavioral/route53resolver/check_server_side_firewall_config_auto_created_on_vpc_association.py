"""server-side-firewall-config-auto-created-on-vpc-association."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-firewall-config-auto-created-on-vpc-association"
GROUP = "server-side"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A fresh VPC already has a default fail-closed FirewallConfig in Get and ListFirewallConfigs.

    Associating a rule group leaves that config's Id and FirewallFailOpen=DISABLED unchanged.
    """
    r53r = ctx.client("route53resolver")
    ec2 = ctx.client("ec2")

    vpc_id = _create_vpc(ctx, ec2)

    baseline = _get_config_or_none(r53r, vpc_id)
    assert baseline is not None, "expected a default FirewallConfig to already exist for a fresh VPC"
    assert baseline["ResourceId"] == vpc_id
    assert baseline["FirewallFailOpen"] == "DISABLED", (
        f"expected the default to be fail-closed (DISABLED), got {baseline['FirewallFailOpen']!r}"
    )

    listed = [
        c
        for page in r53r.get_paginator("list_firewall_configs").paginate()
        for c in page["FirewallConfigs"]
    ]
    assert any(c["Id"] == baseline["Id"] for c in listed), "default config missing from ListFirewallConfigs"

    group_id = _create_rule_group(ctx, r53r)
    assoc_id = r53r.associate_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-r53r-afrg-"),
        FirewallRuleGroupId=group_id,
        VpcId=vpc_id,
        Priority=101,
        Name=ctx.unique_name("sim2real-fwassoc-")[:64],
        MutationProtection="DISABLED",
    )["FirewallRuleGroupAssociation"]["Id"]
    ctx.on_cleanup(lambda: _safe_disassociate(r53r, assoc_id))

    after = _get_config_or_none(r53r, vpc_id)
    assert after is not None, "config disappeared from the VPC after a rule group association"
    assert after["Id"] == baseline["Id"], (
        f"expected association to leave the pre-existing config in place, "
        f"got a different Id: {baseline['Id']!r} -> {after['Id']!r}"
    )
    assert after["FirewallFailOpen"] == "DISABLED", (
        f"expected the fail-closed default to survive association unchanged, got "
        f"{after['FirewallFailOpen']!r}"
    )


def _get_config_or_none(r53r, vpc_id):
    try:
        return r53r.get_firewall_config(ResourceId=vpc_id)["FirewallConfig"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _create_vpc(ctx, ec2):
    name = ctx.unique_name("sim2real-r53r-vpc-")
    resp = ec2.create_vpc(
        CidrBlock="10.0.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    vpc_id = resp["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return vpc_id


def _create_rule_group(ctx, r53r):
    group_id = r53r.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-r53r-crg-"),
        Name=ctx.unique_name("sim2real-fwgroup-")[:64],
    )["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(lambda: _safe_delete_group(r53r, group_id))
    return group_id


def _safe_delete_group(r53r, group_id):
    try:
        r53r.delete_firewall_rule_group(FirewallRuleGroupId=group_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_disassociate(r53r, assoc_id, timeout_s=300.0):
    """Disassociate, then wait until the association is gone: the rule group and VPC stay in use
    while it is still DELETING."""
    try:
        r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=assoc_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"association {assoc_id} still present after {timeout_s}s")
        time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
