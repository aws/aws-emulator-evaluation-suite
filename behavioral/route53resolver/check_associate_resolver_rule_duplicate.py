"""associate-resolver-rule-duplicate."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "associate-resolver-rule-duplicate"
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


def _client_error(fn):
    """The ``Error`` of the ClientError ``fn`` raises. A call that succeeds fails the check: a
    target accepting what AWS refuses must not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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


def _create_system_rule(ctx, r53):
    """Create a SYSTEM rule: VPC-associable and needs no Resolver endpoint, so it is fast."""
    rule_id = r53.create_resolver_rule(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        RuleType="SYSTEM",
        DomainName=f"{ctx.unique_name('sim2real-behav-zone-')}.example.internal.",
        Name=ctx.unique_name("sim2real-behav-rr-"),
    )["ResolverRule"]["Id"]
    ctx.on_cleanup(lambda x=rule_id: _delete_resolver_rule(r53, x))
    _poll(
        lambda: r53.get_resolver_rule(ResolverRuleId=rule_id)["ResolverRule"]["Status"],
        lambda s: s == "COMPLETE",
        timeout_s=60,
        interval_s=2,
        description="SYSTEM resolver rule reaches COMPLETE",
    )
    return rule_id


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-associating a rule already associated with the VPC raises ResourceExistsException.

    The rejected duplicate must not leave a second association behind.
    """
    r53 = ctx.client("route53resolver")
    vpc_id, _subnets, _sg = _create_test_vpc_with_subnets(ctx, 2)
    rule_id = _create_system_rule(ctx, r53)

    r53.associate_resolver_rule(
        ResolverRuleId=rule_id, VPCId=vpc_id, Name=ctx.unique_name("sim2real-behav-rra-")
    )
    ctx.on_cleanup(lambda rr=rule_id, v=vpc_id: _disassoc_resolver_rule(r53, rr, v))

    def assoc_ready():
        assocs = r53.list_resolver_rule_associations(
            Filters=[{"Name": "ResolverRuleId", "Values": [rule_id]}]
        )["ResolverRuleAssociations"]
        return next((a for a in assocs if a["VPCId"] == vpc_id), None)

    # The association is created asynchronously; wait for it to settle to COMPLETE.
    _poll(assoc_ready, lambda a: a is not None and a["Status"] == "COMPLETE",
          timeout_s=180, interval_s=5, description="resolver rule association reaches COMPLETE")

    err = _client_error(
        lambda: r53.associate_resolver_rule(ResolverRuleId=rule_id, VPCId=vpc_id)
    )
    assert err["Code"] == "ResourceExistsException", (
        f"expected ResourceExistsException re-associating an already-associated rule, got {err}"
    )
    assert err["Message"] == (
        f'[RSLVR-00704] Resolver rule "{rule_id}" is already associated with VPC "{vpc_id}".'
    ), err

    # A target that returns the right error but duplicates anyway is still overly permissive.
    assocs = r53.list_resolver_rule_associations(
        Filters=[{"Name": "ResolverRuleId", "Values": [rule_id]}, {"Name": "VPCId", "Values": [vpc_id]}]
    )["ResolverRuleAssociations"]
    assert len(assocs) == 1, (
        f"expected exactly 1 association between {rule_id} and {vpc_id} after the rejected "
        f"duplicate, found {len(assocs)}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
