"""e2e-firewall-domain-blocklist-lifecycle-flow."""
from __future__ import annotations

import re
import time
from typing import Any

from behavioral_harness import tags

CHECK = "e2e-firewall-domain-blocklist-lifecycle-flow"
GROUP = "server-side"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """End-to-end: a BLOCK domain list wired into a rule group and associated to a VPC
    reaches a COMPLETE association with the BLOCK rule bound, then full teardown removes
    the association, rule group and domain list, observably."""
    r53r = ctx.client("route53resolver")
    vpc_id = _create_vpc(ctx)

    blocked_domain = f"blocked-{ctx.unique_name('sim2real-')}.test"

    domain_list_name = ctx.unique_name("sim2real-r53r-dl-")
    domain_list = r53r.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        Name=domain_list_name,
        Tags=[{"Key": "Name", "Value": domain_list_name}],
    )["FirewallDomainList"]
    domain_list_id = domain_list["Id"]
    ctx.on_cleanup(lambda: _safe_delete_domain_list(ctx, domain_list_id))

    r53r.update_firewall_domains(
        FirewallDomainListId=domain_list_id, Operation="ADD", Domains=[blocked_domain]
    )
    _poll_until(
        lambda: r53r.get_firewall_domain_list(FirewallDomainListId=domain_list_id)[
            "FirewallDomainList"
        ]["Status"],
        lambda s: s == "COMPLETE",
        timeout_s=60.0,
        interval_s=2.0,
    )
    domains = r53r.list_firewall_domains(FirewallDomainListId=domain_list_id)["Domains"]
    # Route 53 Resolver DNS Firewall normalizes stored domains to lowercase with a
    # trailing FQDN dot appended.
    expected_blocked_domain = blocked_domain.lower() + "."
    assert expected_blocked_domain in domains, (
        f"expected {expected_blocked_domain!r} in domain list, got {domains}"
    )

    rule_group_name = ctx.unique_name("sim2real-r53r-rg-")
    rule_group = r53r.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        Name=rule_group_name,
        Tags=[{"Key": "Name", "Value": rule_group_name}],
    )["FirewallRuleGroup"]
    rule_group_id = rule_group["Id"]
    ctx.on_cleanup(lambda: _safe_delete_rule_group(ctx, rule_group_id))

    r53r.create_firewall_rule(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        FirewallRuleGroupId=rule_group_id,
        FirewallDomainListId=domain_list_id,
        Priority=10,
        Action="BLOCK",
        BlockResponse="NODATA",
        Name=ctx.unique_name("sim2real-r53r-rule-"),
    )
    ctx.on_cleanup(lambda: _safe_delete_rule(ctx, rule_group_id, domain_list_id))

    assoc_name = ctx.unique_name("sim2real-r53r-assoc-")
    assoc = r53r.associate_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        FirewallRuleGroupId=rule_group_id,
        VpcId=vpc_id,
        Priority=102,
        Name=assoc_name,
        MutationProtection="DISABLED",
        Tags=[{"Key": "Name", "Value": assoc_name}],
    )["FirewallRuleGroupAssociation"]
    assoc_id = assoc["Id"]
    ctx.on_cleanup(lambda: _safe_disassociate(ctx, assoc_id))

    _poll_until(
        lambda: r53r.get_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=assoc_id
        )["FirewallRuleGroupAssociation"],
        lambda a: a["Status"] == "COMPLETE",
        timeout_s=90.0,
        interval_s=3.0,
    )

    rules = r53r.list_firewall_rules(FirewallRuleGroupId=rule_group_id)["FirewallRules"]
    assert len(rules) == 1, f"expected exactly 1 firewall rule in group, got {rules}"
    assert rules[0]["Action"] == "BLOCK", f"expected Action=BLOCK, got {rules[0]['Action']!r}"
    assert rules[0]["FirewallDomainListId"] == domain_list_id, (
        f"expected rule bound to domain list {domain_list_id!r}, "
        f"got {rules[0]['FirewallDomainListId']!r}"
    )

    # --- Full teardown, asserted as the observed consequence, not merely cleanup. ---
    r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=assoc_id)
    _poll_until(
        lambda: _get_assoc_or_none(ctx, assoc_id),
        lambda v: v is None,
        timeout_s=90.0,
        interval_s=3.0,
    )

    # A FirewallRuleGroup can't be deleted while it still has firewall rules in it --
    # delete the rule (identified by group + domain list, not a separate rule id) first.
    r53r.delete_firewall_rule(FirewallRuleGroupId=rule_group_id, FirewallDomainListId=domain_list_id)
    _poll_until(
        lambda: r53r.list_firewall_rules(FirewallRuleGroupId=rule_group_id)["FirewallRules"],
        lambda rs: len(rs) == 0,
        timeout_s=60.0,
        interval_s=2.0,
    )

    # DeleteFirewallRuleGroup can lag briefly behind the association's disappearance
    # (eventual consistency on the backend link), so retry through ConflictException.
    _retry_on_conflict(
        lambda: r53r.delete_firewall_rule_group(FirewallRuleGroupId=rule_group_id),
        timeout_s=60.0,
        interval_s=3.0,
    )
    _poll_until(
        lambda: _get_rule_group_or_none(ctx, rule_group_id),
        lambda v: v is None,
        timeout_s=60.0,
        interval_s=2.0,
    )

    r53r.delete_firewall_domain_list(FirewallDomainListId=domain_list_id)
    _poll_until(
        lambda: _get_domain_list_or_none(ctx, domain_list_id),
        lambda v: v is None,
        timeout_s=60.0,
        interval_s=2.0,
    )

    assert _get_assoc_or_none(ctx, assoc_id) is None, (
        f"association {assoc_id!r} still visible via GetFirewallRuleGroupAssociation after delete"
    )
    assert _get_rule_group_or_none(ctx, rule_group_id) is None, (
        f"rule group {rule_group_id!r} still visible via GetFirewallRuleGroup after delete"
    )
    assert _get_domain_list_or_none(ctx, domain_list_id) is None, (
        f"domain list {domain_list_id!r} still visible via GetFirewallDomainList after delete"
    )

    # Gone from every listing, and unusable.
    assert domain_list_id not in _ids(
        r53r.get_paginator("list_firewall_domain_lists").paginate(), "FirewallDomainLists"
    ), f"deleted domain list {domain_list_id!r} is still listed"
    assert rule_group_id not in _ids(
        r53r.get_paginator("list_firewall_rule_groups").paginate(), "FirewallRuleGroups"
    ), f"deleted rule group {rule_group_id!r} is still listed"
    assert assoc_id not in _ids(
        r53r.get_paginator("list_firewall_rule_group_associations").paginate(VpcId=vpc_id),
        "FirewallRuleGroupAssociations",
    ), f"deleted association {assoc_id!r} is still listed for {vpc_id}"
    from botocore.exceptions import ClientError

    try:
        r53r.update_firewall_domains(
            FirewallDomainListId=domain_list_id, Operation="ADD", Domains=[blocked_domain]
        )
    except ClientError as exc:
        _assert_not_found_shape(exc, domain_list_id, "UpdateFirewallDomains on the deleted list")
    else:
        raise AssertionError(f"UpdateFirewallDomains on the deleted list {domain_list_id!r} succeeded")

    # A mutation on the dead rule group and on the dead association is refused the same way.
    _assert_dead_mutation(
        lambda: r53r.create_firewall_rule(
            CreatorRequestId=ctx.unique_name("sim2real-cr-"),
            FirewallRuleGroupId=rule_group_id,
            FirewallDomainListId=domain_list_id,
            Priority=11,
            Action="BLOCK",
            BlockResponse="NODATA",
            Name=ctx.unique_name("sim2real-r53r-rule-"),
        ),
        rule_group_id,
        "CreateFirewallRule on the deleted rule group",
    )
    _assert_dead_mutation(
        lambda: r53r.update_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=assoc_id, Name=ctx.unique_name("sim2real-r53r-assoc-")
        ),
        assoc_id,
        "UpdateFirewallRuleGroupAssociation on the deleted association",
    )


def _retry_on_conflict(fn, *, timeout_s: float = 60.0, interval_s: float = 3.0) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConflictException" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_vpc(ctx: Any) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-r53r-vpc-")
    vpc = ec2.create_vpc(
        CidrBlock="10.92.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _safe_delete_vpc(ctx, vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return vpc_id


def _tolerate(fn, *codes: str) -> None:
    """Teardown call that tolerates only the given not-found codes (the body already deleted it)."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in codes:
            raise


def _safe_delete_vpc(ctx: Any, vpc_id: str) -> None:
    _tolerate(lambda: ctx.client("ec2").delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound")


def _safe_delete_domain_list(ctx: Any, domain_list_id: str) -> None:
    _tolerate(
        lambda: ctx.client("route53resolver").delete_firewall_domain_list(
            FirewallDomainListId=domain_list_id
        ),
        "ResourceNotFoundException",
    )


def _safe_disassociate(ctx: Any, assoc_id: str) -> None:
    _tolerate(
        lambda: ctx.client("route53resolver").disassociate_firewall_rule_group(
            FirewallRuleGroupAssociationId=assoc_id
        ),
        "ResourceNotFoundException",
    )


def _safe_delete_rule(ctx: Any, rule_group_id: str, domain_list_id: str) -> None:
    _tolerate(
        lambda: ctx.client("route53resolver").delete_firewall_rule(
            FirewallRuleGroupId=rule_group_id, FirewallDomainListId=domain_list_id
        ),
        "ResourceNotFoundException",
    )


def _safe_delete_rule_group(ctx: Any, rule_group_id: str) -> None:
    _tolerate(
        lambda: ctx.client("route53resolver").delete_firewall_rule_group(
            FirewallRuleGroupId=rule_group_id
        ),
        "ResourceNotFoundException",
    )


def _assert_dead_mutation(fn, resource_id: str, what: str) -> None:
    """fn() on a deleted resource must be ResourceNotFoundException + 400 + the exact message."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        _assert_not_found_shape(exc, resource_id, what)
        return
    raise AssertionError(f"{what}: expected ResourceNotFoundException, the call succeeded")


def _assert_not_found_shape(exc, resource_id: str, what: str) -> None:
    """ResourceNotFoundException, HTTP 400 and AWS's RSLVR-02025 message naming the id; the
    trace id that ends the message is per request."""
    code = exc.response.get("Error", {}).get("Code")
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    message = exc.response.get("Error", {}).get("Message") or ""
    assert code == "ResourceNotFoundException", f"{what}: expected ResourceNotFoundException, got {code!r}"
    assert status == 400, f"{what}: ResourceNotFoundException for {resource_id} with HTTP {status!r}, expected 400"
    message_head, _, trace = message.partition(" Trace Id: ")
    expected_message = f'[RSLVR-02025] Can’t find the resource with ID "{resource_id}".'
    assert message_head == expected_message, f"{what}: expected the message {expected_message!r}, got {message!r}"
    assert re.fullmatch(r'"1-[0-9a-f]{8}-[0-9a-f]{24}"', trace), f"{what}: unexpected trace id in {message!r}"


def _ids(pages, key: str) -> list:
    return [item["Id"] for page in pages for item in page.get(key, [])]


def _get_assoc_or_none(ctx: Any, assoc_id: str) -> dict | None:
    from botocore.exceptions import ClientError

    try:
        return ctx.client("route53resolver").get_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=assoc_id
        )["FirewallRuleGroupAssociation"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            _assert_not_found_shape(exc, assoc_id, "GetFirewallRuleGroupAssociation after delete")
            return None
        raise


def _get_rule_group_or_none(ctx: Any, rule_group_id: str) -> dict | None:
    from botocore.exceptions import ClientError

    try:
        return ctx.client("route53resolver").get_firewall_rule_group(
            FirewallRuleGroupId=rule_group_id
        )["FirewallRuleGroup"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            _assert_not_found_shape(exc, rule_group_id, "GetFirewallRuleGroup after delete")
            return None
        raise


def _get_domain_list_or_none(ctx: Any, domain_list_id: str) -> dict | None:
    from botocore.exceptions import ClientError

    try:
        return ctx.client("route53resolver").get_firewall_domain_list(
            FirewallDomainListId=domain_list_id
        )["FirewallDomainList"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            _assert_not_found_shape(exc, domain_list_id, "GetFirewallDomainList after delete")
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
