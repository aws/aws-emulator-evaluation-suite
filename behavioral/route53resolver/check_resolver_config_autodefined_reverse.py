"""resolver-config-autodefined-reverse."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "resolver-config-autodefined-reverse"
GROUP = 'resolver-config'
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
        lambda v=vpc_id: _wait_until(lambda: _try(ec2.delete_vpc, VpcId=v), timeout_s=180)
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
            VpcId=vpc_id,
            CidrBlock=f"10.90.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": TAGS_KV}],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(
            lambda s=sid: _wait_until(lambda: _try(ec2.delete_subnet, SubnetId=s), timeout_s=180)
        )

    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=ctx.unique_name("sim2real-behav-r53r-sg-"),
        Description="route53resolver behavioral test sg",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": TAGS_KV}],
    )["GroupId"]
    ctx.on_cleanup(
        lambda s=sg_id: _wait_until(
            lambda: _try(ec2.delete_security_group, GroupId=s), timeout_s=180
        )
    )

    return vpc_id, subnet_ids, sg_id


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Disabling AutodefinedReverse on a fresh VPC reports DISABLING, then settles to DISABLED.

    GetResolverConfig keeps the same ResolverConfig id, and ListResolverConfigs agrees.
    """
    r53 = ctx.client("route53resolver")
    vpc_id, _subnets, _sg = _create_test_vpc_with_subnets(ctx, 2)

    def probe():
        return r53.get_resolver_config(ResourceId=vpc_id)["ResolverConfig"]

    before = probe()
    assert before["ResourceId"] == vpc_id, before
    assert before["AutodefinedReverse"] == "ENABLED", before

    try:
        updated = r53.update_resolver_config(
            ResourceId=vpc_id, AutodefinedReverseFlag="DISABLE"
        )["ResolverConfig"]
        assert updated["ResourceId"] == vpc_id, updated
        assert updated["AutodefinedReverse"] == "DISABLING", (
            f"UpdateResolverConfig's own response must report the transitional "
            f"DISABLING state, not settle inline: got {updated!r}"
        )

        # Settling to DISABLED can take minutes.
        settled = _poll(
            probe,
            lambda r: r["AutodefinedReverse"] == "DISABLED",
            timeout_s=150,
            interval_s=5,
            description="AutodefinedReverse settles to DISABLED",
        )
        assert settled["Id"] == before["Id"], (settled, before)

        listed = [
            c
            for page in r53.get_paginator("list_resolver_configs").paginate()
            for c in page["ResolverConfigs"]
        ]
        match = next((c for c in listed if c["ResourceId"] == vpc_id), None)
        assert match is not None, listed
        assert match["AutodefinedReverse"] == "DISABLED", match
    finally:
        # Restore the VPC to AutodefinedReverse-ENABLED once the transition has settled.
        try:
            _poll(
                probe,
                lambda r: r["AutodefinedReverse"] in ("DISABLED", "ENABLED"),
                timeout_s=150,
                interval_s=5,
                description="AutodefinedReverse settles",
            )
        except Exception:
            pass
        try:
            r53.update_resolver_config(ResourceId=vpc_id, AutodefinedReverseFlag="ENABLE")
        except Exception:
            pass

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
