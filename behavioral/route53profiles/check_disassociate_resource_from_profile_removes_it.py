"""disassociate-resource-from-profile-removes-it."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disassociate-resource-from-profile-removes-it"
GROUP = "state"
SERVICES = ["route53profiles"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisassociateResourceFromProfile removes the resource association; it disappears from Get/List."""
    r53p = ctx.client("route53profiles")

    profile_id = _create_profile(ctx)
    rule_group_arn = _create_firewall_rule_group(ctx)

    assoc_id = r53p.associate_resource_to_profile(
        ProfileId=profile_id,
        ResourceArn=rule_group_arn,
        Name=ctx.unique_name("sim2real-behav-resassoc-"),
        ResourceProperties=json.dumps({"priority": 150}),
    )["ProfileResourceAssociation"]["Id"]

    assoc_status = _poll_until(
        probe=lambda: r53p.get_profile_resource_association(ProfileResourceAssociationId=assoc_id)[
            "ProfileResourceAssociation"
        ]["Status"],
        predicate=lambda s: s in ("COMPLETE", "FAILED"),
        timeout_s=90,
        interval_s=3,
    )
    assert assoc_status == "COMPLETE", (
        f"resource association settled into {assoc_status!r} instead of COMPLETE"
    )

    disassoc = r53p.disassociate_resource_from_profile(ProfileId=profile_id, ResourceArn=rule_group_arn)[
        "ProfileResourceAssociation"
    ]
    assert disassoc["Id"] == assoc_id
    assert disassoc["Status"] in ("DELETING", "DELETED")

    _poll_until(
        probe=lambda: _is_gone(
            lambda: r53p.get_profile_resource_association(ProfileResourceAssociationId=assoc_id)
        ),
        predicate=bool,
        timeout_s=90,
        interval_s=3,
    )
    error = _client_error(
        lambda: r53p.get_profile_resource_association(ProfileResourceAssociationId=assoc_id)
    )
    assert error["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {error['Code']!r}"
    expected_message = f'[RSLVR-05200] Can\'t locate the Profile association with ID: "{assoc_id}".'
    assert error["Message"] == expected_message, f"expected {expected_message!r}, got {error['Message']!r}"

    remaining = r53p.list_profile_resource_associations(ProfileId=profile_id)[
        "ProfileResourceAssociations"
    ]
    assert assoc_id not in {a["Id"] for a in remaining}


def _client_error(fn):
    """Call fn(); return its error (Code and Message). An unexpected SUCCESS raises: a target
    that accepts what real AWS refuses must fail loudly, not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _is_gone(fn) -> bool:
    """Poll probe: True once fn() fails not-found, False while it still succeeds."""
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return True
        raise
    return False


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
                Name=name, ClientToken=ctx.unique_name("sim2real-behav-token-")
            )["Profile"]["Id"]
            break
        except ClientError as err:
            if err.response["Error"]["Code"] != "LimitExceededException" or time.monotonic() > deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: _delete_profile_blocking(r53p, profile_id))
    return profile_id


def _delete_profile_blocking(r53p, profile_id: str) -> None:
    try:
        r53p.delete_profile(ProfileId=profile_id)
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
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
        CreatorRequestId=ctx.unique_name("sim2real-behav-crid-"), Name=name
    )["FirewallRuleGroup"]
    rule_group_id = rule_group["Id"]
    ctx.on_cleanup(lambda: resolver.delete_firewall_rule_group(FirewallRuleGroupId=rule_group_id))
    return rule_group["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
