"""get-firewall-rule-group-association-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-firewall-rule-group-association-not-found"
GROUP = "error-semantics"
SERVICES = ["route53resolver"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetFirewallRuleGroupAssociation for a nonexistent id is refused with
    ResourceNotFoundException naming it, while a real association is returned; once disassociated,
    reading it and disassociating it again are refused the same way.
    """
    r53r = ctx.client("route53resolver")

    bogus_id = ctx.unique_name("sim2real-behav-frga-")
    code, message = _error(lambda: r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=bogus_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = f'[RSLVR-02025] Can\u2019t find the resource with ID "{bogus_id}".'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: a real association must be retrievable.
    vpc_id = _create_vpc(ctx)
    group_id = _create_firewall_rule_group(ctx)
    assoc = r53r.associate_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-creq-"),
        FirewallRuleGroupId=group_id,
        VpcId=vpc_id,
        Priority=101,
        Name=ctx.unique_name("sim2real-behav-assoc-"),
    )["FirewallRuleGroupAssociation"]
    assoc_id = assoc["Id"]
    ctx.on_cleanup(lambda: _disassociate_best_effort(r53r, assoc_id))

    got = r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)
    got_assoc = got["FirewallRuleGroupAssociation"]
    assert got_assoc["Id"] == assoc_id, f"expected association id {assoc_id!r}, got {got_assoc['Id']!r}"
    assert got_assoc["VpcId"] == vpc_id, f"expected VpcId {vpc_id!r}, got {got_assoc['VpcId']!r}"

    # Disassociate what this check created, then prove it is genuinely gone -- the
    # same read must eventually flip to the specific not-found code (disassociation is
    # asynchronous: the association passes through DELETING before it vanishes), and a
    # further mutation on the dead id must fail the same way.
    r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=assoc_id)
    _poll_until(
        lambda: _still_present(
            lambda: r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)
        ),
        lambda still: not still,
        timeout_s=120,
        interval_s=5,
    )
    not_found = f'[RSLVR-02025] Can\u2019t find the resource with ID "{assoc_id}".'
    gone_code, gone_message = _error(
        lambda: r53r.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)
    )
    assert gone_code == "ResourceNotFoundException", (
        f"expected a disassociated association to read back ResourceNotFoundException, got {gone_code}"
    )
    assert gone_message == not_found, f"expected message {not_found!r}, got {gone_message!r}"
    redissociate_code, redissociate_message = _error(
        lambda: r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=assoc_id)
    )
    assert redissociate_code == "ResourceNotFoundException", (
        f"expected a second disassociate on the dead id to fail with ResourceNotFoundException, "
        f"got {redissociate_code}"
    )
    assert redissociate_message == not_found, (
        f"expected message {not_found!r}, got {redissociate_message!r}"
    )


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


def _disassociate_best_effort(r53r, assoc_id: str) -> None:
    try:
        r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=assoc_id)
    except r53r.exceptions.ResourceNotFoundException:
        pass


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _create_vpc(ctx) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-vpc-")
    vpc = ec2.create_vpc(
        CidrBlock="10.77.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    return vpc_id


def _create_firewall_rule_group(ctx) -> str:
    r53r = ctx.client("route53resolver")
    name = ctx.unique_name("sim2real-behav-frg-")
    group = r53r.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-creq-"),
        Name=name,
    )["FirewallRuleGroup"]
    group_id = group["Id"]
    ctx.on_cleanup(lambda: r53r.delete_firewall_rule_group(FirewallRuleGroupId=group_id))
    return group_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
