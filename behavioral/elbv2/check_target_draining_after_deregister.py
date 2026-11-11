"""target-draining-after-deregister."""
from __future__ import annotations

import ipaddress

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "target-draining-after-deregister"
GROUP = "state"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeregisterTargets moves a registered target into the 'draining' health state."""
    net = _default_vpc_and_subnets(ctx)
    elbv2 = ctx.client("elbv2")
    tg = _create_target_group(ctx, net["vpc_id"])
    # A target only transitions through 'draining' on deregistration if it was actually in
    # service under a load balancer. A target group that isn't associated with a load balancer
    # never runs health checks, so its targets go straight from registration to 'unused' -- there
    # is no in-service state to drain out of.
    lb = _create_alb(ctx, net["subnet_ids"])
    _wait_for_lb_active(ctx, lb["LoadBalancerArn"])
    listener = elbv2.create_listener(
        LoadBalancerArn=lb["LoadBalancerArn"],
        Protocol="HTTP",
        Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}],
    )["Listeners"][0]
    listener_arn = listener["ListenerArn"]
    # Delete the listener explicitly, and before the target group. DeleteLoadBalancer cascades to
    # its listeners too, but that cascade is not immediately consistent with DeleteTargetGroup's own
    # "still referenced by a listener" check, so relying on it alone leaves DeleteTargetGroup
    # racing ResourceInUseException. An explicit DeleteListener clears that reference synchronously.
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_listener(ListenerArn=listener_arn)))
    _poll_until(
        lambda: elbv2.describe_target_groups(TargetGroupArns=[tg["TargetGroupArn"]])["TargetGroups"][0].get(
            "LoadBalancerArns", []
        ),
        lambda arns: lb["LoadBalancerArn"] in arns,
        timeout_s=30,
        interval_s=2,
    )
    target_ip = _pick_ip(net["subnet_cidrs"][0], offset=20)
    target = {"Id": target_ip, "Port": 80}

    elbv2.register_targets(TargetGroupArn=tg["TargetGroupArn"], Targets=[target])
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.deregister_targets(TargetGroupArn=tg["TargetGroupArn"], Targets=[target])))

    # Confirm registration landed, and health checking has actually started (state moves out of
    # 'unused'), before deregistering.
    registered_state = _poll_until(
        lambda: elbv2.describe_target_health(TargetGroupArn=tg["TargetGroupArn"], Targets=[target])[
            "TargetHealthDescriptions"
        ][0]["TargetHealth"]["State"],
        lambda s: s != "unused",
        timeout_s=30,
        interval_s=2,
    )
    # A freshly-registered IP target that doesn't correspond to a real running host has no
    # actual health-check listener behind it, so the very first non-"unused" observation can
    # land on "unavailable" (e.g. Elb.InternalError while the health checker fails to even
    # reach the address) just as readily as "unhealthy" (a clean timeout/refused connection),
    # before eventually settling. Either is a legitimate "no longer unused" in-service state.
    assert registered_state in ("initial", "healthy", "unhealthy", "unavailable"), (
        f"expected the target to be in service before deregistering, got {registered_state}"
    )

    elbv2.deregister_targets(TargetGroupArn=tg["TargetGroupArn"], Targets=[target])

    state = _poll_until(
        lambda: elbv2.describe_target_health(TargetGroupArn=tg["TargetGroupArn"], Targets=[target])[
            "TargetHealthDescriptions"
        ][0]["TargetHealth"]["State"],
        lambda s: s in ("draining", "unused"),
        timeout_s=30,
        interval_s=2,
    )
    assert state == "draining", f"expected draining state right after deregister, got {state}"


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


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    import time as _t

    deadline = _t.monotonic() + timeout_s
    last = None
    while _t.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        _t.sleep(interval_s)
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


def _tags_kv():
    return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-elbv2"}]


def _delete_target_group_retrying(elbv2, arn, attempts=5, delay_s=3):
    # DeleteLoadBalancer runs first (LIFO) and detaches this target group's listener, but AWS's
    # control plane can take a few seconds to stop reporting the target group as in-use, so an
    # immediate DeleteTargetGroup can 400 with ResourceInUseException even though the load
    # balancer is already gone. Retry that specific error; anything else (including "already
    # gone") is terminal.
    import time as _t

    from botocore.exceptions import ClientError

    for attempt in range(attempts):
        try:
            elbv2.delete_target_group(TargetGroupArn=arn)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "TargetGroupNotFoundException":
                return
            if code == "ResourceInUseException" and attempt < attempts - 1:
                _t.sleep(delay_s)
                continue
            raise


def _create_target_group(ctx, vpc_id, **kwargs):
    elbv2 = ctx.client("elbv2")
    name = kwargs.pop("Name", None) or ctx.unique_name("sim2real-elbv2-tg-")
    params = {"Name": name, "Protocol": "HTTP", "Port": 80, "VpcId": vpc_id, "TargetType": "ip"}
    params.update(kwargs)
    params.setdefault("Tags", _tags_kv())
    resp = elbv2.create_target_group(**params)
    tg = resp["TargetGroups"][0]
    arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_retrying(elbv2, arn))
    return tg


def _create_alb(ctx, subnet_ids, name=None):
    elbv2 = ctx.client("elbv2")
    name = name or ctx.unique_name("sim2real-elbv2-lb-")
    resp = elbv2.create_load_balancer(Name=name, Subnets=subnet_ids, Type="application", Tags=_tags_kv())
    lb = resp["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_load_balancer(LoadBalancerArn=arn)))
    return lb


def _wait_for_lb_active(ctx, arn, timeout_s=180, interval_s=5):
    elbv2 = ctx.client("elbv2")
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]["State"]["Code"],
        lambda code: code == "active",
        timeout_s=timeout_s,
        interval_s=interval_s,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
