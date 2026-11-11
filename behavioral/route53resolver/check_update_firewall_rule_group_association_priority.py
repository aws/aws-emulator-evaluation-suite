"""update-firewall-rule-group-association-priority."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "update-firewall-rule-group-association-priority"
GROUP = 'firewall-rule-group-association'
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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateFirewallRuleGroupAssociation actually changes the stored Priority value."""
    r53 = ctx.client("route53resolver")
    group_id = r53.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"), Name=ctx.unique_name("sim2real-behav-frg-")
    )["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(lambda x=group_id: r53.delete_firewall_rule_group(FirewallRuleGroupId=x))
    vpc_id, _subnets, _sg = _create_test_vpc_with_subnets(ctx, 2)

    assoc_id = r53.associate_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        FirewallRuleGroupId=group_id,
        VpcId=vpc_id,
        Priority=400,
        Name=ctx.unique_name("sim2real-behav-assoc-"),
    )["FirewallRuleGroupAssociation"]["Id"]
    ctx.on_cleanup(lambda x=assoc_id: _disassoc_frg(r53, x))
    def assoc_status():
        return r53.get_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=assoc_id
        )["FirewallRuleGroupAssociation"]["Status"]

    _poll(assoc_status, lambda s: s == "COMPLETE", timeout_s=70, interval_s=3)

    r53.update_firewall_rule_group_association(
        FirewallRuleGroupAssociationId=assoc_id, Priority=401
    )

    def priority_is_401():
        return r53.get_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=assoc_id
        )["FirewallRuleGroupAssociation"]["Priority"]

    _poll(priority_is_401, lambda p: p == 401, timeout_s=45, interval_s=3)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
