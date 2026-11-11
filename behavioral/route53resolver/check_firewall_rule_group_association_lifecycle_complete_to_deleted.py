"""firewall-rule-group-association-lifecycle-complete-to-deleted."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firewall-rule-group-association-lifecycle-complete-to-deleted"
GROUP = "state-machine"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A firewall rule group association moves from COMPLETE (after AssociateFirewallRuleGroup
    settles) to gone (GetFirewallRuleGroupAssociation returns ResourceNotFoundException) after
    DisassociateFirewallRuleGroup finishes -- not left as a stale COMPLETE/DELETING record."""
    ec2 = ctx.client("ec2")
    r53r = ctx.client("route53resolver")

    vpc_id = _create_vpc(ctx, ec2, "10.94.0.0/16")

    rule_group_id = r53r.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-fwassoc-rg-req-"),
        Name=ctx.unique_name("sim2real-fwassoc-rg-")[:64],
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: r53r.delete_firewall_rule_group(FirewallRuleGroupId=rule_group_id)))

    association = r53r.associate_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-fwassoc-req-"),
        FirewallRuleGroupId=rule_group_id,
        VpcId=vpc_id,
        Priority=101,
        Name=ctx.unique_name("sim2real-fwassoc-")[:64],
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )["FirewallRuleGroupAssociation"]
    assoc_id = association["Id"]
    ctx.on_cleanup(lambda: _disassociate_and_wait(r53r, assoc_id))

    status = _poll_until(
        lambda: r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)[
            "FirewallRuleGroupAssociation"
        ]["Status"],
        lambda s: s == "COMPLETE",
        timeout_s=180,
        interval_s=5,
    )
    assert status == "COMPLETE", f"association reached {status}, not COMPLETE"

    r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=assoc_id)
    present = _poll_until(
        lambda: _still_present(
            lambda: r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)
        ),
        lambda still: not still,
        timeout_s=180,
        interval_s=3,
    )
    assert not present, f"association {assoc_id} still readable 180s after disassociate"
    not_found = f'[RSLVR-02025] Can\u2019t find the resource with ID "{assoc_id}".'
    gone_code, gone_message = _error(
        lambda: r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)
    )
    assert gone_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after disassociate, got {gone_code!r}"
    )
    assert gone_message == not_found, f"expected message {not_found!r}, got {gone_message!r}"

    redisassociate_code, redisassociate_message = _error(
        lambda: r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=assoc_id)
    )
    assert redisassociate_code == "ResourceNotFoundException", (
        f"expected a second DisassociateFirewallRuleGroup on the dead id to fail with "
        f"ResourceNotFoundException, got {redisassociate_code!r}"
    )
    assert redisassociate_message == not_found, (
        f"expected message {not_found!r}, got {redisassociate_message!r}"
    )

    remaining = r53r.list_firewall_rule_group_associations(VpcId=vpc_id).get(
        "FirewallRuleGroupAssociations", []
    )
    assert all(a["Id"] != assoc_id for a in remaining), (
        f"disassociated association {assoc_id} still present in ListFirewallRuleGroupAssociations"
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


def _disassociate_and_wait(r53r, assoc_id: str) -> None:
    """Teardown: remove the association if the check did not, and wait until it is gone."""
    try:
        r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=assoc_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise
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
