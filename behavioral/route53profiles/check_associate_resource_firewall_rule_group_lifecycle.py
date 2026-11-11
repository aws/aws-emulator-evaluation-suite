"""associate-resource-firewall-rule-group-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "associate-resource-firewall-rule-group-lifecycle"
GROUP = "state"
SERVICES = ["route53profiles"]
TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateResourceToProfile links a DNS Firewall rule group to a Profile and it settles COMPLETE."""
    r53p = ctx.client("route53profiles")

    profile_id = _create_profile(ctx)
    rule_group_arn = _create_firewall_rule_group(ctx)

    assoc_name = ctx.unique_name("sim2real-behav-resassoc-")
    assoc = r53p.associate_resource_to_profile(
        ProfileId=profile_id,
        ResourceArn=rule_group_arn,
        Name=assoc_name,
        ResourceProperties=json.dumps({"priority": 101}),
    )["ProfileResourceAssociation"]
    assoc_id = assoc["Id"]
    ctx.on_cleanup(
        lambda: r53p.disassociate_resource_from_profile(ProfileId=profile_id, ResourceArn=rule_group_arn)
    )

    assert assoc["ProfileId"] == profile_id, f"expected ProfileId {profile_id!r}, got {assoc['ProfileId']!r}"
    assert assoc["ResourceArn"] == rule_group_arn, (
        f"expected ResourceArn {rule_group_arn!r}, got {assoc['ResourceArn']!r}"
    )
    assert assoc["Name"] == assoc_name, f"expected Name {assoc_name!r}, got {assoc['Name']!r}"

    status = _poll_until(
        probe=lambda: r53p.get_profile_resource_association(ProfileResourceAssociationId=assoc_id)[
            "ProfileResourceAssociation"
        ]["Status"],
        predicate=lambda s: s in ("COMPLETE", "FAILED"),
        timeout_s=90,
        interval_s=3,
    )
    assert status == "COMPLETE", f"resource association settled into {status!r} instead of COMPLETE"

    fetched = r53p.get_profile_resource_association(ProfileResourceAssociationId=assoc_id)[
        "ProfileResourceAssociation"
    ]
    assert fetched["ResourceType"] == "FIREWALL_RULE_GROUP", (
        f"expected ResourceType 'FIREWALL_RULE_GROUP', got {fetched['ResourceType']!r}"
    )
    fetched_priority = json.loads(fetched["ResourceProperties"])["priority"]
    assert fetched_priority == 101, f"expected persisted priority 101, got {fetched_priority!r}"

    listed = r53p.list_profile_resource_associations(ProfileId=profile_id)["ProfileResourceAssociations"]
    assert any(a["Id"] == assoc_id for a in listed), (
        f"association {assoc_id!r} missing from list_profile_resource_associations for profile {profile_id!r}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


def _create_profile(ctx) -> str:
    r53p = ctx.client("route53profiles")
    name = ctx.unique_name("sim2real-behav-profile-")
    profile_id = r53p.create_profile(
        Name=name, ClientToken=ctx.unique_name("sim2real-behav-token-"), Tags=TAGS_KV
    )["Profile"]["Id"]
    ctx.on_cleanup(lambda: r53p.delete_profile(ProfileId=profile_id))
    return profile_id


def _create_firewall_rule_group(ctx) -> str:
    resolver = ctx.client("route53resolver")
    name = ctx.unique_name("sim2real-behav-frg-")
    rule_group = resolver.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-crid-"), Name=name, Tags=TAGS_KV
    )["FirewallRuleGroup"]
    rule_group_id = rule_group["Id"]
    ctx.on_cleanup(lambda: resolver.delete_firewall_rule_group(FirewallRuleGroupId=rule_group_id))
    return rule_group["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
