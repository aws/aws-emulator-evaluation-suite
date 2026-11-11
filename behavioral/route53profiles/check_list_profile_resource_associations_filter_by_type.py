"""list-profile-resource-associations-filter-by-type."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-profile-resource-associations-filter-by-type"
GROUP = "state"
SERVICES = ["route53profiles"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListProfileResourceAssociations' ResourceType filter includes matches and excludes mismatches."""
    r53p = ctx.client("route53profiles")

    profile_id = _create_profile(ctx)
    rule_group_arn = _create_firewall_rule_group(ctx)

    assoc_id = r53p.associate_resource_to_profile(
        ProfileId=profile_id,
        ResourceArn=rule_group_arn,
        Name=ctx.unique_name("sim2real-behav-resassoc-"),
        ResourceProperties=json.dumps({"priority": 120}),
    )["ProfileResourceAssociation"]["Id"]
    ctx.on_cleanup(
        lambda: r53p.disassociate_resource_from_profile(ProfileId=profile_id, ResourceArn=rule_group_arn)
    )

    _poll_until(
        probe=lambda: r53p.get_profile_resource_association(ProfileResourceAssociationId=assoc_id)[
            "ProfileResourceAssociation"
        ]["Status"],
        predicate=lambda s: s in ("COMPLETE", "FAILED"),
        timeout_s=90,
        interval_s=3,
    )

    matching = r53p.list_profile_resource_associations(
        ProfileId=profile_id, ResourceType="FIREWALL_RULE_GROUP"
    )["ProfileResourceAssociations"]
    assert assoc_id in {a["Id"] for a in matching}

    mismatched = r53p.list_profile_resource_associations(
        ProfileId=profile_id, ResourceType="RESOLVER_QUERY_LOG_CONFIG"
    )["ProfileResourceAssociations"]
    assert assoc_id not in {a["Id"] for a in mismatched}


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
    deadline = time.monotonic() + 400
    while True:
        try:
            profile_id = r53p.create_profile(
                Name=name,
                ClientToken=ctx.unique_name("sim2real-behav-token-"),
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )["Profile"]["Id"]
            break
        except ClientError as err:
            if err.response["Error"]["Code"] != "LimitExceededException" or time.monotonic() > deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: _delete_profile_blocking(r53p, profile_id))
    return profile_id


def _delete_when_released(call, timeout_s: float = 180.0) -> bool:
    """Run a delete, retrying the ConflictException AWS returns while an association is still
    being removed; False when the resource is already gone."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            call()
            return True
        except ClientError as err:
            error = err.response["Error"]
            if error["Code"] == "ResourceNotFoundException":
                return False
            if error["Code"] != "ConflictException" or "associated" not in error["Message"]:
                raise
            if time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _delete_profile_blocking(r53p, profile_id: str) -> None:
    if not _delete_when_released(lambda: r53p.delete_profile(ProfileId=profile_id)):
        return
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            r53p.get_profile(ProfileId=profile_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(3)


def _create_firewall_rule_group(ctx) -> str:
    resolver = ctx.client("route53resolver")
    name = ctx.unique_name("sim2real-behav-frg-")
    rule_group = resolver.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-crid-"),
        Name=name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["FirewallRuleGroup"]
    rule_group_id = rule_group["Id"]
    ctx.on_cleanup(lambda: _delete_when_released(
        lambda: resolver.delete_firewall_rule_group(FirewallRuleGroupId=rule_group_id)))
    return rule_group["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
