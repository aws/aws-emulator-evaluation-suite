"""associate-firewall-rule-group-duplicate-priority-conflict."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "associate-firewall-rule-group-duplicate-priority-conflict"
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


def _err_code(fn):
    """Call fn(); return botocore Error.Code of the ClientError it raises. A call that
    succeeds fails the check: a target accepting what AWS refuses must not read as an
    error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), _without_trace_id(error.get("Message"))
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_test_vpc_with_subnets(ctx, subnet_count=2):
    """Return (vpc_id, [subnet_ids], sg_id) usable for resolver testing.

    Prefers a dedicated, self-created VPC (full isolation). If the account forbids
    VPC creation or is at quota, borrows the shared network's subnets -- borrowed
    resources are never registered for teardown.
    """
    ec2 = ctx.client("ec2")
    vpc_id = None
    subnet_ids = []
    try:
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
    except Exception:
        vpc_id = None

    if vpc_id is not None:
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
    else:
        defaults = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
        if not defaults:
            raise AssertionError("cannot create a VPC and no shared network VPC exists to borrow")
        vpc_id = defaults[0]["VpcId"]
        seen_azs = set()
        for sn in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]:
            if sn["AvailabilityZone"] in seen_azs:
                continue
            seen_azs.add(sn["AvailabilityZone"])
            subnet_ids.append(sn["SubnetId"])
            if len(subnet_ids) == subnet_count:
                break
        if len(subnet_ids) < subnet_count:
            raise AssertionError(
                f"shared network VPC {vpc_id} has fewer than {subnet_count} subnets in distinct AZs"
            )

    sg_id = None
    try:
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
    except Exception:
        groups = ec2.describe_security_groups(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "group-name", "Values": ["default"]},
            ]
        )["SecurityGroups"]
        if not groups:
            raise AssertionError(f"no usable security group in VPC {vpc_id}") from None
        sg_id = groups[0]["GroupId"]

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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two FirewallRuleGroup associations on one VPC cannot share a Priority: group_b at group_a's
    Priority is rejected and never appears in ListFirewallRuleGroupAssociations. Once group_a
    moves off that Priority, the identical group_b call succeeds."""
    r53 = ctx.client("route53resolver")
    group_a = r53.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"), Name=ctx.unique_name("sim2real-behav-frg-")
    )["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(lambda x=group_a: r53.delete_firewall_rule_group(FirewallRuleGroupId=x))
    group_b = r53.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"), Name=ctx.unique_name("sim2real-behav-frg-")
    )["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(lambda x=group_b: r53.delete_firewall_rule_group(FirewallRuleGroupId=x))
    vpc_id, _subnets, _sg = _create_test_vpc_with_subnets(ctx, 2)

    assoc_a = r53.associate_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        FirewallRuleGroupId=group_a,
        VpcId=vpc_id,
        Priority=300,
        Name=ctx.unique_name("sim2real-behav-assoc-"),
    )["FirewallRuleGroupAssociation"]["Id"]
    ctx.on_cleanup(lambda x=assoc_a: _disassoc_frg(r53, x))

    def _assoc_a_status():
        return r53.get_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=assoc_a
        )["FirewallRuleGroupAssociation"]["Status"]

    _poll(
        _assoc_a_status,
        lambda s: s == "COMPLETE",
        timeout_s=70,
        interval_s=3,
        description="positive-control association reaching COMPLETE",
    )

    code, message = _err_code(
        lambda: r53.associate_firewall_rule_group(
            CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
            FirewallRuleGroupId=group_b,
            VpcId=vpc_id,
            Priority=300,
            Name=ctx.unique_name("sim2real-behav-assoc-"),
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a duplicate association priority, got {code}"
    )
    expected = (
        f'[RSLVR-02303] This priority is the same with another association: "{assoc_a}" . '
        "Try again with another priority number."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    live_at_300 = r53.list_firewall_rule_group_associations(VpcId=vpc_id, Priority=300)[
        "FirewallRuleGroupAssociations"
    ]
    live_ids_at_300 = {a["Id"] for a in live_at_300}
    assert live_ids_at_300 == {assoc_a}, (
        f"expected only the positive-control association {assoc_a} live at Priority=300 "
        f"after the rejected duplicate, got {live_ids_at_300}"
    )

    r53.update_firewall_rule_group_association(
        FirewallRuleGroupAssociationId=assoc_a, Priority=301
    )

    def _assoc_a_priority():
        return r53.get_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=assoc_a
        )["FirewallRuleGroupAssociation"]["Priority"]

    _poll(
        _assoc_a_priority,
        lambda p: p == 301,
        timeout_s=45,
        interval_s=3,
        description="restore leg: positive-control association moved off Priority=300",
    )

    assoc_b = r53.associate_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        FirewallRuleGroupId=group_b,
        VpcId=vpc_id,
        Priority=300,
        Name=ctx.unique_name("sim2real-behav-assoc-"),
    )["FirewallRuleGroupAssociation"]["Id"]
    ctx.on_cleanup(lambda x=assoc_b: _disassoc_frg(r53, x))

    live_at_300_after_restore = _poll(
        lambda: r53.list_firewall_rule_group_associations(VpcId=vpc_id, Priority=300)[
            "FirewallRuleGroupAssociations"
        ],
        lambda assocs: {a["Id"] for a in assocs} == {assoc_b},
        timeout_s=70,
        interval_s=3,
        description="identical call now succeeds: group_b live at Priority=300 once the conflict is gone",
    )
    assert {a["Id"] for a in live_at_300_after_restore} == {assoc_b}, (
        f"expected only group_b's association {assoc_b} live at Priority=300 after the "
        f"conflict was resolved, got {[a['Id'] for a in live_at_300_after_restore]}"
    )


_TRACE_ID = ' Trace Id: "'


def _without_trace_id(message):
    """The message minus Route 53 Resolver's per-request ' Trace Id: "..."' suffix."""
    message = message or ""
    head, sep, _ = message.rpartition(_TRACE_ID)
    return head if sep and message.endswith('"') else message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
