"""firewall-association-mutation-protection-blocks-disassociate-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "firewall-association-mutation-protection-blocks-disassociate-rejected"
GROUP = "server-side"
SERVICES = ["route53resolver"]

_TAGS = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """Disassociating a MutationProtection=ENABLED association fails ValidationException with the exact
    message and leaves it COMPLETE, an unprotected sibling disassociates, and once protection is
    DISABLED and the association COMPLETE the identical disassociate succeeds.
    """
    r53r = ctx.client("route53resolver")
    vpc_id = _create_test_vpc(ctx)
    protected_priority, control_priority = _unused_priorities(ctx, r53r, vpc_id, count=2)

    protected_group = r53r.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        Name=ctx.unique_name("sim2real-r53r-rg-prot-"),
        Tags=_TAGS,
    )["FirewallRuleGroup"]
    protected_group_id = protected_group["Id"]
    ctx.on_cleanup(lambda: _safe_delete_rule_group(ctx, protected_group_id))

    control_group = r53r.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        Name=ctx.unique_name("sim2real-r53r-rg-ctrl-"),
        Tags=_TAGS,
    )["FirewallRuleGroup"]
    control_group_id = control_group["Id"]
    ctx.on_cleanup(lambda: _safe_delete_rule_group(ctx, control_group_id))

    protected_assoc = r53r.associate_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        FirewallRuleGroupId=protected_group_id,
        VpcId=vpc_id,
        Priority=protected_priority,
        Name=ctx.unique_name("sim2real-r53r-assoc-prot-"),
        MutationProtection="ENABLED",
        Tags=_TAGS,
    )["FirewallRuleGroupAssociation"]
    protected_assoc_id = protected_assoc["Id"]

    def _unlock_and_disassociate_protected() -> None:
        if _get_assoc_or_none(ctx, protected_assoc_id) is None:
            return
        try:
            r53r.update_firewall_rule_group_association(
                FirewallRuleGroupAssociationId=protected_assoc_id, MutationProtection="DISABLED"
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        _poll_until(
            lambda: _get_assoc_or_none(ctx, protected_assoc_id),
            lambda v: v is None or v["Status"] == "COMPLETE",
            timeout_s=120.0,
            interval_s=3.0,
        )
        _disassociate_and_wait(ctx, protected_assoc_id)

    ctx.on_cleanup(_unlock_and_disassociate_protected)

    _poll_until(
        lambda: r53r.get_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=protected_assoc_id
        )["FirewallRuleGroupAssociation"]["Status"],
        lambda s: s == "COMPLETE",
        timeout_s=90.0,
        interval_s=3.0,
    )

    control_assoc = r53r.associate_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        FirewallRuleGroupId=control_group_id,
        VpcId=vpc_id,
        Priority=control_priority,
        Name=ctx.unique_name("sim2real-r53r-assoc-ctrl-"),
        MutationProtection="DISABLED",
        Tags=_TAGS,
    )["FirewallRuleGroupAssociation"]
    control_assoc_id = control_assoc["Id"]
    ctx.on_cleanup(lambda: _disassociate_and_wait(ctx, control_assoc_id))
    _poll_until(
        lambda: r53r.get_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=control_assoc_id
        )["FirewallRuleGroupAssociation"]["Status"],
        lambda s: s == "COMPLETE",
        timeout_s=90.0,
        interval_s=3.0,
    )

    # --- Break exactly one thing: disassociate the protected association. ---
    code, message = _error(
        lambda: r53r.disassociate_firewall_rule_group(
            FirewallRuleGroupAssociationId=protected_assoc_id
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        "[RSLVR-02307] The DNS Firewall rule group association is under mutation protection. "
        "Remove the mutation protection and try again."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # --- Effect absent: the protected association is still COMPLETE, untouched. ---
    still_there = r53r.get_firewall_rule_group_association(
        FirewallRuleGroupAssociationId=protected_assoc_id
    )["FirewallRuleGroupAssociation"]
    assert still_there["Status"] == "COMPLETE", (
        f"expected Status='COMPLETE' after the rejected disassociate, got {still_there['Status']!r}"
    )
    assert still_there["MutationProtection"] == "ENABLED", (
        "expected MutationProtection='ENABLED' to survive the rejected disassociate, got "
        f"{still_there['MutationProtection']!r}"
    )

    # --- Positive control: the unprotected sibling disassociates cleanly. ---
    r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=control_assoc_id)
    _poll_until(
        lambda: _get_assoc_or_none(ctx, control_assoc_id),
        lambda v: v is None,
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert _get_assoc_or_none(ctx, control_assoc_id) is None, (
        "expected the unprotected control association to disappear after disassociate"
    )

    # --- Restore: disabling protection on the SAME association permits the identical
    # disassociate call to succeed, where it was rejected above. ---
    r53r.update_firewall_rule_group_association(
        FirewallRuleGroupAssociationId=protected_assoc_id, MutationProtection="DISABLED"
    )
    # The update leaves the association UPDATING; disassociating then is an invalid transition
    # (ConflictException), so wait for COMPLETE with protection DISABLED first.
    unlocked = _poll_until(
        lambda: r53r.get_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=protected_assoc_id
        )["FirewallRuleGroupAssociation"],
        lambda a: a["Status"] == "COMPLETE" and a["MutationProtection"] == "DISABLED",
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert unlocked["MutationProtection"] == "DISABLED", (
        f"expected MutationProtection='DISABLED' after the update, got {unlocked['MutationProtection']!r}"
    )
    disassoc = r53r.disassociate_firewall_rule_group(
        FirewallRuleGroupAssociationId=protected_assoc_id
    )["FirewallRuleGroupAssociation"]
    assert disassoc["Id"] == protected_assoc_id, (
        f"expected the disassociate to name {protected_assoc_id}, got {disassoc['Id']!r}"
    )
    assert disassoc["Status"] == "DELETING", (
        f"expected Status='DELETING' once protection was disabled, got {disassoc['Status']!r}"
    )
    _poll_until(
        lambda: _get_assoc_or_none(ctx, protected_assoc_id),
        lambda v: v is None,
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert _get_assoc_or_none(ctx, protected_assoc_id) is None, (
        "expected the once-protected association to disappear once protection was disabled"
    )


def _create_test_vpc(ctx: Any) -> str:
    """A firewall rule group association only needs a VpcId (no subnets), so a bare,
    dedicated VPC avoids depending on an ambient default VPC that a freshly provisioned
    account may not have."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.87.0.0/16",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": _TAGS + [{"Key": "Name", "Value": ctx.unique_name("sim2real-r53r-vpc-")}],
            }
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe_delete_vpc(ctx, vpc_id))
    return vpc_id


def _safe_delete_vpc(ctx: Any, vpc_id: str) -> None:
    try:
        ctx.client("ec2").delete_vpc(VpcId=vpc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
            raise


def _unused_priorities(ctx: Any, r53r: Any, vpc_id: str, count: int = 2) -> list[int]:
    """Firewall rule group association priorities must be unique per VPC across ALL
    associations (including ones left over from other test runs), so pick priorities
    that are demonstrably not already in use rather than hardcoding fixed numbers."""
    import random

    in_use: set[int] = set()
    paginator = r53r.get_paginator("list_firewall_rule_group_associations")
    for page in paginator.paginate(VpcId=vpc_id):
        for assoc in page.get("FirewallRuleGroupAssociations", []):
            in_use.add(assoc["Priority"])

    chosen: list[int] = []
    while len(chosen) < count:
        candidate = random.randint(300, 9000)
        if candidate not in in_use and candidate not in chosen:
            chosen.append(candidate)
    return chosen


def _safe_delete_rule_group(ctx: Any, rule_group_id: str) -> None:
    try:
        ctx.client("route53resolver").delete_firewall_rule_group(
            FirewallRuleGroupId=rule_group_id
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected SUCCESS raises,
    because an emulator accepting a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), _without_trace_id(err.get("Message"))
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _disassociate_and_wait(ctx: Any, assoc_id: str) -> None:
    """Disassociate (tolerating already gone) and wait until the association disappears."""
    from botocore.exceptions import ClientError

    try:
        ctx.client("route53resolver").disassociate_firewall_rule_group(
            FirewallRuleGroupAssociationId=assoc_id
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        if _get_assoc_or_none(ctx, assoc_id) is None:
            return
        time.sleep(5)
    raise RuntimeError(f"firewall rule group association {assoc_id} never disappeared")


def _get_assoc_or_none(ctx: Any, assoc_id: str) -> dict | None:
    from botocore.exceptions import ClientError

    try:
        return ctx.client("route53resolver").get_firewall_rule_group_association(
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


_TRACE_ID = ' Trace Id: "'


def _without_trace_id(message):
    """The message minus Route 53 Resolver's per-request ' Trace Id: "..."' suffix."""
    message = message or ""
    head, sep, _ = message.rpartition(_TRACE_ID)
    return head if sep and message.endswith('"') else message


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
