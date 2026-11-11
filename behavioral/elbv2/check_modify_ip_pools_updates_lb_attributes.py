"""modify-ip-pools-updates-lb-attributes."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-ip-pools-updates-lb-attributes"
GROUP = "state-machine"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """ModifyIpPools refuses a freshly created, unprovisioned public-scope IPAM pool.

    The refusal is the exact ValidationError "IPAM pool must have locale set to 'None'.", no pool
    is attached to the load balancer, and an unrelated LB attribute change on it is applied.
    """

    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")

    az_to_subnet = _default_vpc_azs_subnets(ctx, min_azs=2)
    azs = sorted(az_to_subnet.keys())[:2]
    name = _short_alnum_name(ctx, "sim2real-ipp")
    lb = elbv2.create_load_balancer(
        Name=name,
        Subnets=[az_to_subnet[a] for a in azs],
        Type="application",
        Scheme="internet-facing",
    )["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))
    _wait_lb_not_provisioning(ctx, lb_arn)

    # Positive control: an unrelated elbv2 mutation on this same LB succeeds and is
    # reflected on an independent read, proving elbv2 credentials/permissions are healthy.
    elbv2.modify_load_balancer_attributes(
        LoadBalancerArn=lb_arn,
        Attributes=[{"Key": "idle_timeout.timeout_seconds", "Value": "70"}],
    )
    control_attrs = {
        a["Key"]: a["Value"]
        for a in elbv2.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)["Attributes"]
    }
    assert control_attrs.get("idle_timeout.timeout_seconds") == "70", (
        f"positive control failed: expected idle_timeout.timeout_seconds=70, "
        f"got {control_attrs.get('idle_timeout.timeout_seconds')!r}"
    )

    pool_id = _create_empty_public_ipam_pool(ctx)

    try:
        elbv2.modify_ip_pools(LoadBalancerArn=lb_arn, IpamPools={"Ipv4IpamPoolId": pool_id})
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"]["Message"]
        assert code == "ValidationError", (
            f"expected ValidationError for a freshly created, unprovisioned public IPAM "
            f"pool, got {code}: {message}"
        )
        assert message == "IPAM pool must have locale set to 'None'.", (
            f"expected the account's own deterministic refusal message, got: {message!r}"
        )
    else:
        raise AssertionError(
            f"expected ModifyIpPools to refuse pool {pool_id} (no provisioned CIDR), "
            "but it returned success"
        )

    attrs_after = {
        a["Key"]: a["Value"]
        for a in elbv2.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)["Attributes"]
    }
    assert attrs_after.get("ipv4.ipam.ipv4pool.id", "") in ("", None), (
        f"the refused pool must not be attached, got "
        f"ipv4.ipam.ipv4pool.id={attrs_after.get('ipv4.ipam.ipv4pool.id')!r}"
    )


def _short_alnum_name(ctx, prefix: str, max_len: int = 32) -> str:
    raw = ctx.unique_name(f"{prefix}-").replace("_", "-").lower()
    if len(raw) > max_len:
        raw = raw[-max_len:]
    raw = raw.strip("-")
    return raw


def _default_vpc_azs_subnets(ctx, min_azs: int = 2) -> dict:

    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < min_azs:
        raise AssertionError(
            f"shared network VPC spans only {len(by_az)} AZs, need at least {min_azs}"
        )
    return by_az


def _create_empty_public_ipam_pool(ctx, timeout_s: float = 120.0) -> str:
    """Create an IPAM with a public-scope IPv4 pool that has zero provisioned CIDRs.

    No BYOIP authorization needed: the pool is created but never provisioned with a CIDR,
    which is exactly the "not a usable IP pool" state under test.
    """
    ec2 = ctx.client("ec2")
    tag_spec = [
        {
            "ResourceType": "ipam",
            "Tags": [{"Key": "sim2real-check", "Value": CHECK}],
        }
    ]
    ipam = ec2.create_ipam(
        Description=_short_alnum_name(ctx, "sim2real-ipam", max_len=255),
        OperatingRegions=[{"RegionName": ctx.region}],
        Tier="free",
        TagSpecifications=tag_spec,
    )["Ipam"]
    ipam_id = ipam["IpamId"]
    # DeleteIpam's Cascade cannot remove a pool in the PUBLIC scope (only private-scope pools
    # and pools with a source resource) -- so the pool must be deleted explicitly, and its
    # cleanup registered AFTER the ipam's so LIFO teardown deletes the pool first.
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id))
    ipam = _wait_ipam_create_complete(ctx, ipam_id, timeout_s)
    public_scope_id = ipam["PublicDefaultScopeId"]

    pool = ec2.create_ipam_pool(
        IpamScopeId=public_scope_id,
        AddressFamily="ipv4",
        TagSpecifications=[
            {
                "ResourceType": "ipam-pool",
                "Tags": [{"Key": "sim2real-check", "Value": CHECK}],
            }
        ],
    )["IpamPool"]
    pool_id = pool["IpamPoolId"]

    def _delete_pool() -> None:
        ec2.delete_ipam_pool(IpamPoolId=pool_id)
        _wait_ipam_pool_delete_complete(ctx, pool_id, timeout_s)

    ctx.on_cleanup(_delete_pool)
    _wait_ipam_pool_create_complete(ctx, pool_id, timeout_s)
    return pool_id


def _wait_ipam_create_complete(ctx, ipam_id: str, timeout_s: float) -> dict:
    ec2 = ctx.client("ec2")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        ipam = ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"][0]
        state = ipam["State"]
        if state == "create-complete":
            return ipam
        if state == "create-failed":
            raise AssertionError(f"IPAM {ipam_id} entered create-failed")
        time.sleep(3)
    raise AssertionError(f"IPAM {ipam_id} never reached create-complete")


def _wait_ipam_pool_create_complete(ctx, pool_id: str, timeout_s: float) -> dict:
    ec2 = ctx.client("ec2")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        pool = ec2.describe_ipam_pools(IpamPoolIds=[pool_id])["IpamPools"][0]
        state = pool["State"]
        if state == "create-complete":
            return pool
        if state == "create-failed":
            raise AssertionError(f"IPAM pool {pool_id} entered create-failed")
        time.sleep(3)
    raise AssertionError(f"IPAM pool {pool_id} never reached create-complete")


def _wait_ipam_pool_delete_complete(ctx, pool_id: str, timeout_s: float) -> None:
    ec2 = ctx.client("ec2")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            pools = ec2.describe_ipam_pools(IpamPoolIds=[pool_id])["IpamPools"]
        except ClientError as exc:
            if "NotFound" in exc.response["Error"]["Code"]:
                return
            raise
        if not pools or pools[0]["State"] == "delete-complete":
            return
        time.sleep(5)
    raise AssertionError(f"IPAM pool {pool_id} never reached delete-complete")


def _wait_lb_not_provisioning(ctx, lb_arn: str, timeout_s: float = 180.0) -> None:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        lb = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
        code = lb["State"]["Code"]
        if code != "provisioning":
            return
        time.sleep(3)
    raise AssertionError("load balancer never left 'provisioning' state")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
