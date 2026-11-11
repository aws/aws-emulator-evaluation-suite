"""concurrent-register-deregister-targets-consistent-state."""
from __future__ import annotations

import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor


from behavioral_harness import tags

CHECK = "concurrent-register-deregister-targets-consistent-state"
GROUP = "concurrency"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Interleaved concurrent RegisterTargets/DeregisterTargets calls converge to one consistent final state."""
    vpc = _get_default_vpc(ctx)
    elbv2 = ctx.client("elbv2")

    name = ctx.unique_name("sim2real-tg-")
    # Note: for TargetType "ip" (as for "instance" and "alb"), health checks are always
    # enabled and cannot be disabled -- AWS rejects HealthCheckEnabled=False for this
    # target type with InvalidConfigurationRequestException. Omit the parameter so the
    # (mandatory) default health check configuration is used.
    tg = elbv2.create_target_group(
        Name=name,
        Protocol="HTTP",
        Port=80,
        VpcId=vpc["vpc_id"],
        TargetType="ip",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["TargetGroups"][0]
    tg_arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))
    # No deregistration delay, so a deregistered target leaves draining at once and is removed.
    elbv2.modify_target_group_attributes(
        TargetGroupArn=tg_arn,
        Attributes=[{"Key": "deregistration_delay.timeout_seconds", "Value": "0"}],
    )

    target_ip = _pick_ip_in_cidr(vpc["cidr"])
    target = {"Id": target_ip, "Port": 80}

    # Fire many concurrent RegisterTargets calls for the exact same target.
    # RegisterTargets must be idempotent: no duplicate entries, no lost/duplicated state.
    def _register():
        elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[target])

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(_register) for _ in range(8)]
        for f in futures:
            f.result()

    health = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
    matching = [h for h in health if h["Target"]["Id"] == target_ip]
    assert len(matching) == 1, (
        f"expected exactly one target entry after concurrent idempotent registers, got {len(matching)}"
    )

    # Now fire many concurrent DeregisterTargets calls for the same target.
    def _deregister():
        elbv2.deregister_targets(TargetGroupArn=tg_arn, Targets=[target])

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(_deregister) for _ in range(8)]
        for f in futures:
            f.result()

    def _probe():
        rows = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
        return [h for h in rows if h["Target"]["Id"] == target_ip]

    final = _poll_until(
        _probe,
        lambda rows: not rows,
        timeout_s=max(1.0, min(60.0, (ctx.time_left() or 60.0) - 10.0)),
        interval_s=3.0,
    )
    assert not final, (
        f"target was not removed after concurrent deregisters with deregistration_delay 0 "
        f"(no lost update may leave it registered or draining forever): {final}"
    )

    # Re-check: the converged state must be stable, not flapping.
    second = _probe()
    assert not second, f"deregistered target reappeared on a repeated read: {second}"


def _get_default_vpc(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc = vpcs[0]
    return {"vpc_id": vpc["VpcId"], "cidr": vpc["CidrBlock"]}


def _pick_ip_in_cidr(cidr):
    network = ipaddress.ip_network(cidr, strict=False)
    hosts = network.hosts()
    # AWS reserves the first four IP addresses (and the last one) of every subnet's
    # CIDR block for internal networking purposes (VPC router, DNS, future use).
    # Since the VPC's default subnets typically start right at the VPC CIDR base,
    # skip enough leading addresses to land past that reserved block.
    for _ in range(4):
        next(hosts)
    ip = next(hosts)
    return str(ip)


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last



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
