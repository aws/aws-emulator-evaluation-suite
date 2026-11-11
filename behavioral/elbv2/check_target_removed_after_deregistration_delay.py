"""target-removed-after-deregistration-delay."""
from __future__ import annotations

import ipaddress
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "target-removed-after-deregistration-delay"
GROUP = "state"
SERVICES = ["elbv2"]

# Removal latency at a 0 s delay is undocumented; half the 300 s default delay still fails a target
# that ignores the attribute and drains for the default.
_MAX_REMOVAL_S = 150


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An in-service target under deregistration_delay.timeout_seconds=0 is gone from
    DescribeTargetHealth after DeregisterTargets well before the 300 s default delay elapses."""
    net = _default_vpc_and_subnets(ctx)
    elbv2 = ctx.client("elbv2")
    lb = _create_alb(ctx, net["subnet_ids"])
    _wait_for_lb_active(ctx, lb["LoadBalancerArn"])

    tg = _create_target_group(ctx, net["vpc_id"])
    elbv2.modify_target_group_attributes(
        TargetGroupArn=tg["TargetGroupArn"],
        Attributes=[{"Key": "deregistration_delay.timeout_seconds", "Value": "0"}],
    )
    listener = elbv2.create_listener(
        LoadBalancerArn=lb["LoadBalancerArn"],
        Protocol="HTTP",
        Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}],
    )["Listeners"][0]
    listener_arn = listener["ListenerArn"]
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_listener(ListenerArn=listener_arn)))

    target_ip = _pick_ip(net["subnet_cidrs"][0], offset=25)
    target = {"Id": target_ip, "Port": 80}
    elbv2.register_targets(TargetGroupArn=tg["TargetGroupArn"], Targets=[target])
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.deregister_targets(TargetGroupArn=tg["TargetGroupArn"], Targets=[target])))

    # An unattached group deregisters immediately whatever the delay says; the delay only governs
    # a target in service under a listener, so confirm it left 'unused' before deregistering.
    in_service_state = _poll_until(
        lambda: _health_state(elbv2, tg["TargetGroupArn"], target_ip),
        lambda s: s not in (None, "unused"),
        timeout_s=90,
        interval_s=3,
    )
    assert in_service_state in ("initial", "healthy", "unhealthy", "unavailable"), (
        f"expected the target to be in service before deregistering, got {in_service_state!r}"
    )

    elbv2.deregister_targets(TargetGroupArn=tg["TargetGroupArn"], Targets=[target])

    _poll_until(
        lambda: _health_state(elbv2, tg["TargetGroupArn"], target_ip) is None,
        lambda gone: gone,
        timeout_s=_MAX_REMOVAL_S,
        interval_s=2,
        budget_s=_budget_s(ctx, _MAX_REMOVAL_S),
    )


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ListenerNotFound",
            "LoadBalancerNotFound",
            "TargetGroupNotFound",
        ):
            raise


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0, budget_s=None):
    """Poll until predicate holds; a stop forced by the runner's budget, short of timeout_s, is no verdict."""
    start = time.monotonic()
    stop = start + (timeout_s if budget_s is None else min(timeout_s, budget_s))
    last = None
    while time.monotonic() < stop:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if budget_s is not None and budget_s < timeout_s:
        raise TimeoutError(
            f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
            f"{timeout_s}s wait ended (last={last!r}); not graded"
        )
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


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
        "Name": name, "Protocol": "HTTP", "Port": 80, "VpcId": vpc_id, "TargetType": "ip",
        "Tags": [{"Key": "sim2real:managed", "Value": "true"}],
    }
    params.update(kwargs)
    resp = elbv2.create_target_group(**params)
    tg = resp["TargetGroups"][0]
    arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_target_group_when_free(elbv2, arn)))
    return tg


def _create_alb(ctx, subnet_ids, name=None):
    elbv2 = ctx.client("elbv2")
    name = name or ctx.unique_name("sim2real-elbv2-lb-")
    resp = elbv2.create_load_balancer(
        Name=name, Subnets=subnet_ids, Type="application", Scheme="internal",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    lb = resp["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_load_balancer(LoadBalancerArn=arn)))
    return lb


def _wait_for_lb_active(ctx, arn, timeout_s=240, interval_s=5):
    elbv2 = ctx.client("elbv2")
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]["State"]["Code"],
        lambda code: code == "active",
        timeout_s=timeout_s,
        interval_s=interval_s,
    )


def _health_state(elbv2, tg_arn, target_ip):
    """The target's reported State, or None if it is no longer listed at all.

    Reads the unfiltered list: a Targets=[...] filtered call keeps reporting 'unused' after
    deregistration completes, so it could never observe "gone".
    """
    descs = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
    for desc in descs:
        if desc["Target"]["Id"] == target_ip:
            return desc["TargetHealth"]["State"]
    return None



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
