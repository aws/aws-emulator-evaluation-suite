"""resolver-rule-system-lifecycle-and-association."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "resolver-rule-system-lifecycle-and-association"
GROUP = 'resolver-rule'
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


def _delete_resolver_rule(r53, rule_id):
    """Delete the rule, retrying ResourceInUseException while an association is still being removed."""
    def _attempt():
        try:
            r53.delete_resolver_rule(ResolverRuleId=rule_id)
            return True
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "ResourceNotFoundException":
                return True
            if code == "ResourceInUseException":
                return False
            raise

    _wait_until(_attempt, timeout_s=120)


def _disassoc_resolver_rule(r53, rule_id, vpc_id):
    """Disassociate the rule from the VPC and wait until no association of the rule remains."""
    def _attempt():
        assocs = r53.list_resolver_rule_associations(
            Filters=[{"Name": "ResolverRuleId", "Values": [rule_id]}]
        )["ResolverRuleAssociations"]
        if not assocs:
            return True
        if any(a["VPCId"] == vpc_id and a["Status"] not in ("CREATING", "DELETING") for a in assocs):
            try:
                r53.disassociate_resolver_rule(VPCId=vpc_id, ResolverRuleId=rule_id)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                    raise
        return False

    _wait_until(_attempt, timeout_s=180)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A SYSTEM ResolverRule reaches COMPLETE; its VPC association starts CREATING (provisioning
    is asynchronous) and reaches COMPLETE, graded there with its Get/List projections."""
    r53 = ctx.client("route53resolver")
    domain_name = f"{ctx.unique_name('sim2real-behav-zone-')}.example.internal."
    rule = r53.create_resolver_rule(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        Name=ctx.unique_name("sim2real-behav-rr-"),
        RuleType="SYSTEM",
        DomainName=domain_name,
    )["ResolverRule"]
    rule_id = rule["Id"]
    ctx.on_cleanup(lambda x=rule_id: _delete_resolver_rule(r53, x))
    assert rule["RuleType"] == "SYSTEM", f"expected RuleType=SYSTEM, got {rule['RuleType']}"
    # ResolverRuleStatus models only COMPLETE | DELETING | UPDATING | FAILED -- a SYSTEM rule
    # needs no endpoint and reaches COMPLETE synchronously from CreateResolverRule itself.
    assert rule["Status"] == "COMPLETE", f"expected Status=COMPLETE, got {rule['Status']}"
    assert rule["Id"].startswith("rslvr-rr-"), rule["Id"]

    def rule_status():
        return r53.get_resolver_rule(ResolverRuleId=rule_id)["ResolverRule"]["Status"]

    _poll(
        rule_status,
        lambda s: s == "COMPLETE",
        timeout_s=45,
        interval_s=2,
        description="resolver rule reaches COMPLETE",
    )

    vpc_id, _subnets, _sg = _create_test_vpc_with_subnets(ctx, 2)
    assoc = r53.associate_resolver_rule(
        ResolverRuleId=rule_id, VPCId=vpc_id, Name=ctx.unique_name("sim2real-behav-rra-")
    )["ResolverRuleAssociation"]
    ctx.on_cleanup(lambda rr=rule_id, v=vpc_id: _disassoc_resolver_rule(r53, rr, v))
    assert assoc["Status"] == "CREATING", (
        f"AssociateResolverRule must report Status=CREATING, got {assoc['Status']}"
    )
    assert assoc["VPCId"] == vpc_id, f"expected VPCId={vpc_id}, got {assoc['VPCId']}"
    assert assoc["ResolverRuleId"] == rule_id, (
        f"expected ResolverRuleId={rule_id}, got {assoc['ResolverRuleId']}"
    )
    assert assoc["Id"].startswith("rslvr-rrassoc-"), assoc["Id"]

    early = r53.get_resolver_rule_association(ResolverRuleAssociationId=assoc["Id"])[
        "ResolverRuleAssociation"
    ]
    assert early["Status"] in ("CREATING", "COMPLETE"), early["Status"]

    got = _poll(
        lambda: r53.get_resolver_rule_association(ResolverRuleAssociationId=assoc["Id"])[
            "ResolverRuleAssociation"
        ],
        lambda a: a["Status"] != "CREATING",
        timeout_s=300,
        interval_s=5,
        description="resolver rule association leaves CREATING",
    )
    assert got["Status"] == "COMPLETE", (
        f"expected the association to settle COMPLETE, got {got['Status']!r}: "
        f"{got.get('StatusMessage')!r}"
    )
    assert got["VPCId"] == vpc_id, f"expected VPCId={vpc_id}, got {got['VPCId']}"

    listed = r53.list_resolver_rule_associations(
        Filters=[{"Name": "ResolverRuleId", "Values": [rule_id]}]
    )["ResolverRuleAssociations"]
    assert [(a["Id"], a["Status"]) for a in listed] == [(assoc["Id"], "COMPLETE")], (
        f"ListResolverRuleAssociations for {rule_id}: {listed!r}"
    )

    # ResolverRule carries no association-count field; the independent-read contract
    # this closes is that the rule's own status is untouched by its association.
    rule_after = r53.get_resolver_rule(ResolverRuleId=rule_id)["ResolverRule"]
    assert rule_after["Status"] == "COMPLETE", (
        f"expected Status=COMPLETE, got {rule_after['Status']}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
