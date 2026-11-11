"""mutation-protection-blocks-disassociate."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "mutation-protection-blocks-disassociate"
GROUP = 'overly-permissive'
SERVICES = ['route53resolver']

TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]

def _try(fn, **kwargs):
    """Delete; True once done or already gone, False while a dependency still holds it."""
    try:
        fn(**kwargs)
        return True
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if "NotFound" in code:
            return True
        if code == "DependencyViolation":
            return False
        raise


def _wait_until(probe, timeout_s=120.0, interval_s=2.0):
    """Poll probe() until truthy; raise when the deadline passes first."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if probe():
            return True
        time.sleep(interval_s)
    raise AssertionError(f"teardown condition not met within {timeout_s}s")


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), _without_trace_id(err.get("Message"))
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_test_vpc_with_subnets(ctx, subnet_count=2):
    """Return (vpc_id, [subnet_ids], sg_id) usable for resolver testing.

    Creates a dedicated VPC, its subnets and a security group, each registered
    for teardown, so the check never depends on an account default.
    """
    ec2 = ctx.client("ec2")
    subnet_ids = []
    vpc_id = ec2.create_vpc(CidrBlock="10.90.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(
        lambda v=vpc_id: _wait_until(lambda: _try(ec2.delete_vpc, VpcId=v), timeout_s=120)
    )
    try:
        ec2.create_tags(
            Resources=[vpc_id],
            Tags=TAGS_KV + [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}],
        )
    except Exception:
        pass

    azs = [
        a["ZoneName"]
        for a in ec2.describe_availability_zones(
            Filters=[
                {"Name": "state", "Values": ["available"]},
                {"Name": "opt-in-status", "Values": ["opt-in-not-required"]},
            ]
        )["AvailabilityZones"]
    ][:subnet_count]
    if len(azs) < subnet_count:
        raise AssertionError(
            f"region {ctx.region} exposes only {len(azs)} usable AZs, need {subnet_count}"
        )
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.90.{i}.0/24", AvailabilityZone=az
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(
            lambda s=sid: _wait_until(lambda: _try(ec2.delete_subnet, SubnetId=s), timeout_s=120)
        )

    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=ctx.unique_name("sim2real-behav-r53r-sg-"),
        Description="route53resolver behavioral test sg",
    )["GroupId"]
    ctx.on_cleanup(
        lambda s=sg_id: _wait_until(
            lambda: _try(ec2.delete_security_group, GroupId=s), timeout_s=120
        )
    )

    return vpc_id, subnet_ids, sg_id


def _disassoc_frg(r53, assoc_id):
    """Disable mutation protection, disassociate, and wait until the association is gone.

    ConflictException (the association is mid-update) is retried to the deadline; other errors raise.
    """
    def _attempt():
        try:
            assoc = r53.get_firewall_rule_group_association(
                FirewallRuleGroupAssociationId=assoc_id
            )["FirewallRuleGroupAssociation"]
            if assoc["Status"] == "DELETING":
                return False
            if assoc.get("MutationProtection") == "ENABLED":
                r53.update_firewall_rule_group_association(
                    FirewallRuleGroupAssociationId=assoc_id, MutationProtection="DISABLED"
                )
            r53.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=assoc_id)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return True
            if code != "ConflictException":
                raise
        return False

    _wait_until(_attempt, timeout_s=180)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An association created with MutationProtection=ENABLED cannot be disassociated."""
    r53 = ctx.client("route53resolver")
    group_id = r53.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"), Name=ctx.unique_name("sim2real-behav-frg-")
    )["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(lambda x=group_id: r53.delete_firewall_rule_group(FirewallRuleGroupId=x))
    vpc_id, _subnets, _sg = _create_test_vpc_with_subnets(ctx, 2)

    assoc = r53.associate_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        FirewallRuleGroupId=group_id,
        VpcId=vpc_id,
        Priority=150,
        Name=ctx.unique_name("sim2real-behav-assoc-"),
        MutationProtection="ENABLED",
    )["FirewallRuleGroupAssociation"]
    assoc_id = assoc["Id"]
    ctx.on_cleanup(lambda x=assoc_id: _disassoc_frg(r53, x))
    def assoc_status():
        return r53.get_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=assoc_id
        )["FirewallRuleGroupAssociation"]["Status"]

    _poll(assoc_status, lambda s: s == "COMPLETE", timeout_s=70, interval_s=3)

    code, message = _error(
        lambda: r53.disassociate_firewall_rule_group(
            FirewallRuleGroupAssociationId=assoc_id
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException while MutationProtection=ENABLED, got {code}"
    )
    expected = (
        "[RSLVR-02307] The DNS Firewall rule group association is under mutation protection. "
        "Remove the mutation protection and try again."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the rejected call must not have disturbed the association --
    # an independent read, not the mutating call's own (already-raised) response.
    still_there = r53.get_firewall_rule_group_association(
        FirewallRuleGroupAssociationId=assoc_id
    )["FirewallRuleGroupAssociation"]
    assert still_there["Status"] == "COMPLETE", (
        f"protected association was disturbed by the rejected disassociate, got Status={still_there['Status']!r}"
    )
    assert still_there["MutationProtection"] == "ENABLED", (
        f"protected association's MutationProtection changed despite rejection, got {still_there['MutationProtection']!r}"
    )

    # Turning protection off must then permit the disassociation.
    r53.update_firewall_rule_group_association(
        FirewallRuleGroupAssociationId=assoc_id, MutationProtection="DISABLED"
    )
    disassoc = r53.disassociate_firewall_rule_group(
        FirewallRuleGroupAssociationId=assoc_id
    )["FirewallRuleGroupAssociation"]
    assert disassoc["Id"] == assoc_id, (
        f"expected the disassociate to name {assoc_id}, got {disassoc['Id']!r}"
    )
    assert disassoc["Status"] == "DELETING", (
        f"expected Status=DELETING after disabling protection, got {disassoc['Status']}"
    )

    # Terminal read is independent of the mutating call: confirm the association
    # actually disappears rather than trusting DisassociateFirewallRuleGroup's own response.
    def assoc_gone():
        try:
            r53.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return True
            raise
        return False

    _poll(
        assoc_gone,
        bool,
        timeout_s=120,
        interval_s=3,
        description="association removal after disassociate",
    )
    gone_code, gone_message = _error(
        lambda: r53.get_firewall_rule_group_association(FirewallRuleGroupAssociationId=assoc_id)
    )
    assert gone_code == "ResourceNotFoundException", gone_code
    expected = f'[RSLVR-02025] Can\u2019t find the resource with ID "{assoc_id}".'
    assert gone_message == expected, f"expected message {expected!r}, got {gone_message!r}"


_TRACE_ID = ' Trace Id: "'


def _without_trace_id(message):
    """The message minus Route 53 Resolver's per-request ' Trace Id: "..."' suffix."""
    message = message or ""
    head, sep, _ = message.rpartition(_TRACE_ID)
    return head if sep and message.endswith('"') else message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
