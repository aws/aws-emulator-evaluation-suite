"""deregister-nonexistent-target-is-idempotent."""
from __future__ import annotations

import time
import ipaddress

from behavioral_harness import tags

CHECK = "deregister-nonexistent-target-is-idempotent"
GROUP = "data-plane"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeregisterTargets on a target that was never registered succeeds (per API contract)
    with no invalid-target error and leaves a registered target on the same group untouched."""
    net = _default_vpc_and_subnets(ctx)
    elbv2 = ctx.client("elbv2")
    tg = _create_target_group(ctx, net["vpc_id"])

    # Positive control: a real registered target, so the terminal read below has something it
    # could lose if the implementation mishandles an unknown id instead of trivially no-oping.
    registered = {"Id": _host_ip(net["subnet_cidrs"][0], 10), "Port": 80}
    elbv2.register_targets(TargetGroupArn=tg["TargetGroupArn"], Targets=[registered])

    before = elbv2.describe_target_health(TargetGroupArn=tg["TargetGroupArn"])["TargetHealthDescriptions"]
    assert len(before) == 1 and before[0]["Target"]["Id"] == registered["Id"], (
        f"positive control failed: expected exactly the registered target {registered!r}, got {before!r}"
    )

    never_registered = {"Id": _host_ip(net["subnet_cidrs"][0], 11), "Port": 80}
    # Must not raise; AWS documents that deregistering a target that does not exist succeeds.
    resp = elbv2.deregister_targets(TargetGroupArn=tg["TargetGroupArn"], Targets=[never_registered])
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected deregister_targets on a never-registered target to succeed (200), got {resp!r}"
    )

    # Independent terminal read at the destination: the unrelated registered target must be
    # exactly as it was -- deregistering an unknown id must not touch it.
    after = elbv2.describe_target_health(TargetGroupArn=tg["TargetGroupArn"])["TargetHealthDescriptions"]
    assert len(after) == 1 and after[0]["Target"]["Id"] == registered["Id"], (
        f"deregistering an unrelated, never-registered target must not affect the target that IS "
        f"registered; before={before!r} after={after!r}"
    )


# ===== helpers =====
_GONE = {"TargetGroupNotFound", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"}


def _safe(fn):
    """Teardown: done once the resource is gone; any other failure raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code", "") not in _GONE:
            raise


def _host_ip(cidr, offset):
    net = ipaddress.ip_network(cidr)
    return str(net.network_address + offset)


def _default_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s)
        if len(by_az) >= 2:
            chosen = list(by_az.values())[:2]
            return {
                "vpc_id": vpc_id,
                "subnet_ids": [s["SubnetId"] for s in chosen],
                "subnet_cidrs": [s["CidrBlock"] for s in chosen],
            }

    # No usable shared network in this account/region: create-or-adopt rather than depend on an
    # ambient default that a freshly provisioned account may not have.
    vpc_id = ec2.create_vpc(CidrBlock="10.99.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.create_tags(
        Resources=[vpc_id],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "Name", "Value": ctx.unique_name("sim2real-elbv2-vpc-")}],
    )
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    subnet_ids, subnet_cidrs = [], []
    for i in range(2):
        az = azs[i % len(azs)]["ZoneName"]
        cidr = f"10.99.{i}.0/24"
        sid = ec2.create_subnet(VpcId=vpc_id, CidrBlock=cidr, AvailabilityZone=az)["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=sid: _safe(lambda: ec2.delete_subnet(SubnetId=sid)))
        subnet_ids.append(sid)
        subnet_cidrs.append(cidr)
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "subnet_cidrs": subnet_cidrs}


def _create_target_group(ctx, vpc_id, **kwargs):
    elbv2 = ctx.client("elbv2")
    name = kwargs.pop("Name", None) or ctx.unique_name("sim2real-elbv2-tg-")
    params = {"Name": name, "Protocol": "HTTP", "Port": 80, "VpcId": vpc_id, "TargetType": "ip"}
    params.update(kwargs)
    params.setdefault("Tags", [{"Key": "sim2real:managed", "Value": "true"}])
    resp = elbv2.create_target_group(**params)
    tg = resp["TargetGroups"][0]
    arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_target_group_when_free(elbv2, arn)))
    return tg



def _delete_target_group_when_free(elbv2, arn, timeout_s=600.0, interval_s=2.0):
    """Delete a target group once no listener or deleting load balancer still uses it (ResourceInUse)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.delete_target_group(TargetGroupArn=arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "TargetGroupNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
