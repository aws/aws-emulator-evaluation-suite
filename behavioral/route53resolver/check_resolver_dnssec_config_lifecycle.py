"""resolver-dnssec-config-lifecycle."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "resolver-dnssec-config-lifecycle"
GROUP = 'dnssec-config'
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

    Always a dedicated, self-created VPC. DNSSEC validation is VPC-scoped resolver
    state, so borrowing the account's default VPC would mutate a resource this check
    does not own -- and that other concurrent checks may depend on being left alone.
    A VPC-creation failure is therefore a hard failure, not a fallback.
    """
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.90.0.0/16",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": TAGS_KV + [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}],
            }
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(
        lambda v=vpc_id: _wait_until(lambda: _try(ec2.delete_vpc, VpcId=v), timeout_s=180)
    )

    subnet_ids = []
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
            TagSpecifications=[
                {
                    "ResourceType": "subnet",
                    "Tags": TAGS_KV + [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-subnet-")}],
                }
            ],
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
    """Enabling DNSSEC validation goes ENABLING -> ENABLED and is reflected by Get and List.

    Re-applying the same value is idempotent: it neither errors nor regresses the status.
    """
    r53 = ctx.client("route53resolver")
    vpc_id, _subnets, _sg = _create_test_vpc_with_subnets(ctx, 2)

    def probe():
        return r53.get_resolver_dnssec_config(ResourceId=vpc_id)["ResolverDNSSECConfig"]

    # A DNSSEC flip is asynchronous, so wait for a SETTLED state first instead of assuming one.
    settled = _poll(
        probe,
        lambda r: r["ValidationStatus"] in ("ENABLED", "DISABLED"),
        timeout_s=240,
        interval_s=5,
        description="DNSSEC config settles",
    )
    config_id = settled["Id"]
    assert settled["ResourceId"] == vpc_id, settled

    try:
        updated = r53.update_resolver_dnssec_config(
            ResourceId=vpc_id, Validation="ENABLE"
        )["ResolverDNSSECConfig"]
        assert updated["Id"] == config_id, (updated, config_id)
        assert updated["ResourceId"] == vpc_id, updated
        # ENABLING while the flip propagates, ENABLED if it was already on.
        assert updated["ValidationStatus"] in ("ENABLING", "ENABLED"), updated

        got = probe()
        assert got["Id"] == config_id, got
        assert got["ValidationStatus"] in ("ENABLING", "ENABLED"), got

        listed = r53.list_resolver_dnssec_configs()["ResolverDnssecConfigs"]
        assert any(c["Id"] == config_id for c in listed), listed

        again = r53.update_resolver_dnssec_config(
            ResourceId=vpc_id, Validation="ENABLE"
        )["ResolverDNSSECConfig"]
        assert again["ValidationStatus"] in ("ENABLING", "ENABLED"), again

        # Read back independently rather than trusting the re-apply's own response.
        final = probe()
        assert final["Id"] == config_id, final
        assert final["ValidationStatus"] in ("ENABLING", "ENABLED"), final
        final_listed = r53.list_resolver_dnssec_configs()["ResolverDnssecConfigs"]
        assert any(c["Id"] == config_id for c in final_listed), final_listed

        settled_enabled = _poll(
            probe,
            lambda r: r["ValidationStatus"] != "ENABLING",
            timeout_s=max(1.0, min(240.0, (ctx.time_left() or 240.0) - 5)),
            interval_s=5,
            description="DNSSEC validation leaves ENABLING",
        )
        assert settled_enabled["ValidationStatus"] == "ENABLED", (
            f"ValidationStatus after ENABLE settled to {settled_enabled['ValidationStatus']!r}"
        )
    finally:
        # Restore the VPC to DNSSEC-validation-off once the async transition settles.
        try:
            _poll(
                probe,
                lambda r: r["ValidationStatus"] in ("ENABLED", "DISABLED"),
                timeout_s=150,
                interval_s=5,
                description="DNSSEC config settles before restore",
            )
        except Exception:
            pass
        try:
            r53.update_resolver_dnssec_config(ResourceId=vpc_id, Validation="DISABLE")
        except Exception:
            pass

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
