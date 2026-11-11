"""firewall-rule-group-disassociate-mutation-protection-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firewall-rule-group-disassociate-mutation-protection-rejected"
GROUP = "state-machine"
SERVICES = ["route53resolver"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisassociateFirewallRuleGroup is refused with ValidationException when MutationProtection is
    ENABLED and the association stays COMPLETE and readable, while an unprotected association of the
    same rule group disassociates.
    """
    ec2 = ctx.client("ec2")
    r53r = ctx.client("route53resolver")

    vpc_unprotected = _create_vpc(ctx, ec2, "10.95.0.0/16")
    vpc_protected = _create_vpc(ctx, ec2, "10.96.0.0/16")

    rule_group_id = r53r.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-mutprot-rg-req-"),
        Name=ctx.unique_name("sim2real-mutprot-rg-")[:64],
    )["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: r53r.delete_firewall_rule_group(FirewallRuleGroupId=rule_group_id)))

    protected_assoc_id = r53r.associate_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-mutprot-assoc-req-"),
        FirewallRuleGroupId=rule_group_id,
        VpcId=vpc_protected,
        Priority=_unused_priority(r53r, vpc_protected),
        Name=ctx.unique_name("sim2real-mutprot-protected-")[:64],
        MutationProtection="ENABLED",
    )["FirewallRuleGroupAssociation"]["Id"]
    ctx.on_cleanup(lambda: _teardown_association(r53r, protected_assoc_id))

    unprotected_assoc_id = r53r.associate_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-mutprot-assoc2-req-"),
        FirewallRuleGroupId=rule_group_id,
        VpcId=vpc_unprotected,
        Priority=_unused_priority(r53r, vpc_unprotected),
        Name=ctx.unique_name("sim2real-mutprot-unprotected-")[:64],
        MutationProtection="DISABLED",
    )["FirewallRuleGroupAssociation"]["Id"]
    ctx.on_cleanup(lambda: _teardown_association(r53r, unprotected_assoc_id))

    for assoc_id in (protected_assoc_id, unprotected_assoc_id):
        status = _poll_until(
            lambda assoc_id=assoc_id: r53r.get_firewall_rule_group_association(
                FirewallRuleGroupAssociationId=assoc_id
            )["FirewallRuleGroupAssociation"]["Status"],
            lambda s: s == "COMPLETE",
            timeout_s=180,
            interval_s=5,
        )
        assert status == "COMPLETE", f"association {assoc_id} reached {status}, not COMPLETE"

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

    still_there = r53r.get_firewall_rule_group_association(
        FirewallRuleGroupAssociationId=protected_assoc_id
    )["FirewallRuleGroupAssociation"]
    assert still_there["Status"] == "COMPLETE", (
        f"protected association was disturbed despite rejection: {still_there!r}"
    )

    # Positive control: the unprotected sibling association disassociates successfully.
    r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=unprotected_assoc_id)
    still = _poll_until(
        lambda: _still_present(
            lambda: r53r.get_firewall_rule_group_association(
                FirewallRuleGroupAssociationId=unprotected_assoc_id
            )
        ),
        lambda present: not present,
        timeout_s=180,
        interval_s=3,
    )
    assert not still, "expected the unprotected sibling association to disassociate cleanly"

    # Restore: disabling MutationProtection must then permit the identical disassociate call
    # to succeed against the same association that was just rejected.
    r53r.update_firewall_rule_group_association(
        FirewallRuleGroupAssociationId=protected_assoc_id,
        MutationProtection="DISABLED",
    )
    r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=protected_assoc_id)
    protected_still = _poll_until(
        lambda: _still_present(
            lambda: r53r.get_firewall_rule_group_association(
                FirewallRuleGroupAssociationId=protected_assoc_id
            )
        ),
        lambda present: not present,
        timeout_s=180,
        interval_s=3,
    )
    assert not protected_still, (
        "expected the previously-protected association to disassociate cleanly once "
        "MutationProtection was disabled"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    return value


_TRACE_ID = ' Trace Id: "'


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises, with the
    per-request X-Ray trace id suffix removed. A call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        message = err.get("Message", "")
        head, sep, _ = message.rpartition(_TRACE_ID)
        return err.get("Code"), (head if sep and message.endswith('"') else message)
    raise AssertionError(f"expected a ClientError, the call succeeded and returned {result!r}")


def _still_present(fn) -> bool:
    """True while fn() succeeds; False once it raises ResourceNotFoundException."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return False
        raise
    return True


def _teardown_association(r53r, assoc_id: str) -> None:
    """Teardown: lift mutation protection, disassociate, and wait until the association is gone."""
    _safe(
        lambda: r53r.update_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=assoc_id, MutationProtection="DISABLED"
        )
    )
    _poll_until(
        lambda: _still_present(
            lambda: r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)
        )
        and r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)[
            "FirewallRuleGroupAssociation"
        ]["Status"]
        == "UPDATING",
        lambda updating: not updating,
        timeout_s=120,
        interval_s=3,
    )
    _safe(lambda: r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=assoc_id))
    _poll_until(
        lambda: _still_present(
            lambda: r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)
        ),
        lambda still: not still,
        timeout_s=180,
        interval_s=3,
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _unused_priority(r53r, vpc_id: str) -> int:
    """A priority not already claimed by an existing association in this VPC -- a fixed
    literal collides with associations concurrent runs leave behind in a shared (often
    default) VPC, and Priority must be unique per VPC across ALL associations."""
    import random

    in_use: set[int] = set()
    paginator = r53r.get_paginator("list_firewall_rule_group_associations")
    for page in paginator.paginate(VpcId=vpc_id):
        for assoc in page.get("FirewallRuleGroupAssociations", []):
            in_use.add(assoc["Priority"])
    while True:
        candidate = random.randint(300, 9000)
        if candidate not in in_use:
            return candidate


def _create_vpc(ctx, ec2, cidr: str) -> str:
    """A VPC this check owns, deleted at teardown once its associations are gone."""
    vpc_id = ec2.create_vpc(
        CidrBlock=cidr,
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc(ec2, vpc_id))
    return vpc_id


def _delete_vpc(ec2, vpc_id: str) -> None:
    """Delete the VPC, retrying while a just-removed association still holds it."""
    deadline = time.monotonic() + 300
    while True:
        try:
            ec2.delete_vpc(VpcId=vpc_id)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(10)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
