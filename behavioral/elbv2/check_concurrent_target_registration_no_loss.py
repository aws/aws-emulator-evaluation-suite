"""concurrent-target-registration-no-loss."""
from __future__ import annotations

import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-target-registration-no-loss"
GROUP = "concurrency"
SERVICES = ["elbv2"]

_N_TARGETS = 12


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N targets registered concurrently against the same target group are all durably recorded
    (no lost writes / races) even though RegisterTargets mutates shared target-group state."""
    net = _default_vpc_and_subnets(ctx)
    elbv2 = ctx.client("elbv2")
    tg = _create_target_group(ctx, net["vpc_id"])
    tg_arn = tg["TargetGroupArn"]
    subnet_cidr = net["subnet_cidrs"][0]
    ips = [_pick_ip(subnet_cidr, offset=30 + i) for i in range(_N_TARGETS)]

    def _register(ip):
        elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": ip, "Port": 80}])
        return ip

    ctx.on_cleanup(
        lambda: _safe(
            lambda: elbv2.deregister_targets(
                TargetGroupArn=tg_arn, Targets=[{"Id": ip, "Port": 80} for ip in ips]
            )
        )
    )

    errors = []
    with ThreadPoolExecutor(max_workers=_N_TARGETS) as pool:
        futures = [pool.submit(_register, ip) for ip in ips]
        for f in as_completed(futures):
            try:
                f.result()
            except Exception as e:  # noqa: BLE001
                errors.append(e)

    assert not errors, f"concurrent RegisterTargets raised errors: {errors!r}"

    health = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
    registered_ids = {d["Target"]["Id"] for d in health}
    assert registered_ids == set(ips), (
        f"expected exactly {len(ips)} registered targets, got {len(registered_ids)}: "
        f"missing={set(ips) - registered_ids} extra={registered_ids - set(ips)}"
    )


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TargetGroupNotFound":
            raise


def _default_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s)
    if len(by_az) < 2:
        raise AssertionError("shared network does not have subnets in at least 2 availability zones")
    chosen = list(by_az.values())[:2]
    return {
        "vpc_id": vpc_id,
        "subnet_ids": [s["SubnetId"] for s in chosen],
        "subnet_cidrs": [s["CidrBlock"] for s in chosen],
    }


def _pick_ip(cidr, offset=10):
    net = ipaddress.ip_network(cidr)
    return str(net.network_address + offset)


def _create_target_group(ctx, vpc_id, **kwargs):
    elbv2 = ctx.client("elbv2")
    name = kwargs.pop("Name", None) or ctx.unique_name("sim2real-elbv2-tg-")
    params = {
        "Name": name,
        "Protocol": "HTTP",
        "Port": 80,
        "VpcId": vpc_id,
        "TargetType": "ip",
        "Tags": [{"Key": "sim2real", "Value": "behavioral"}],
    }
    params.update(kwargs)
    resp = elbv2.create_target_group(**params)
    tg = resp["TargetGroups"][0]
    arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_target_group_when_free(elbv2, arn)))
    return tg



def _delete_target_group_when_free(elbv2, arn, timeout_s=600.0, interval_s=10.0):
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
