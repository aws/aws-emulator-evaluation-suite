"""modify-target-group-attributes-deregistration-delay-changes-drain-time."""
from __future__ import annotations

import ipaddress
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "modify-target-group-attributes-deregistration-delay-changes-drain-time"
GROUP = "visibility-timeout-ttl"
SERVICES = ["elbv2"]


# timing:real-time — retention: 5 s https://docs.aws.amazon.com/elasticloadbalancing/latest/application/edit-target-group-attributes.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """Lowering deregistration_delay.timeout_seconds via
    ModifyTargetGroupAttributes shortens how long a deregistering target stays
    visible before it is fully removed -- well under the 300s default."""
    elbv2 = ctx.client("elbv2")
    delay_s = 5
    lb_arn, vpc_id, subnet_ids, _sg = _create_alb(ctx)
    _wait_for_lb_active(ctx, lb_arn)
    tg_arn = _create_target_group(ctx, vpc_id)
    _create_listener_forwarding(ctx, lb_arn, tg_arn)

    elbv2.modify_target_group_attributes(
        TargetGroupArn=tg_arn,
        Attributes=[{"Key": "deregistration_delay.timeout_seconds", "Value": str(delay_s)}],
    )
    attrs = {
        a["Key"]: a["Value"]
        for a in elbv2.describe_target_group_attributes(TargetGroupArn=tg_arn)["Attributes"]
    }
    assert attrs["deregistration_delay.timeout_seconds"] == str(delay_s), (
        f"attribute not persisted: {attrs.get('deregistration_delay.timeout_seconds')!r}"
    )

    target_ip = _fake_ip_in_subnet(ctx, subnet_ids[0])
    elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": target_ip, "Port": 80}])
    ctx.on_cleanup(lambda: _safe_deregister(elbv2, tg_arn, target_ip))
    _poll_until(
        lambda: _target_state(elbv2, tg_arn, target_ip),
        lambda s: s is not None,
        timeout_s=30,
        interval_s=1,
    )

    elbv2.deregister_targets(TargetGroupArn=tg_arn, Targets=[{"Id": target_ip, "Port": 80}])
    dereg_state = _target_state(elbv2, tg_arn, target_ip)
    assert dereg_state == "draining", (
        f"expected the target to enter 'draining' immediately after deregistration, got {dereg_state!r}"
    )

    # On real AWS, DescribeTargetHealth for an explicitly-named Id/Port keeps
    # answering (as "unused", reason Target.NotRegistered) rather than raising
    # InvalidTargetException once deregistration completes -- it does not
    # necessarily disappear/return None. What the shortened delay actually
    # controls is how long the target stays in "draining"; poll for that
    # transition instead of for the target vanishing.
    start = time.monotonic()
    final_state = _poll_until(
        lambda: _target_state(elbv2, tg_arn, target_ip),
        lambda s: s != "draining",
        timeout_s=60,
        interval_s=2,
    )
    elapsed = time.monotonic() - start
    # Two-sided: the delay must be HONORED (not skipped outright) and SHORT (not the
    # unmodified 300s default, nor some other fixed value unrelated to what was
    # configured) -- a target that ignores the configured value entirely, whether by
    # dropping the target instantly or by draining for a fixed unrelated duration,
    # fails one side or the other.
    assert elapsed >= delay_s - 2, (
        f"target left 'draining' after only {elapsed:.1f}s, but "
        f"deregistration_delay.timeout_seconds={delay_s} requires it to stay at least that long"
    )
    # elapsed-bound: the configured 5 s drain, far below the 300 s default, is the behavior.
    assert elapsed < delay_s + 30, (
        f"target took {elapsed:.1f}s to leave 'draining' after deregistration; "
        f"the shortened {delay_s}s delay does not appear to have been enforced"
    )
    assert final_state in (None, "unused"), (
        f"expected the target to settle into a terminal non-draining state after the "
        f"deregistration delay elapsed, got {final_state!r}"
    )


# ===== helpers =====


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _target_state(elbv2, tg_arn: str, target_id: str) -> str | None:
    from botocore.exceptions import ClientError

    try:
        resp = elbv2.describe_target_health(
            TargetGroupArn=tg_arn, Targets=[{"Id": target_id, "Port": 80}]
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "InvalidTargetException":
            return None
        raise
    descs = resp.get("TargetHealthDescriptions", [])
    if not descs:
        return None
    return descs[0]["TargetHealth"]["State"]


def _safe_deregister(elbv2, tg_arn: str, target_id: str) -> None:
    try:
        elbv2.deregister_targets(TargetGroupArn=tg_arn, Targets=[{"Id": target_id, "Port": 80}])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TargetGroupNotFound":
            raise


def _fake_ip_in_subnet(ctx, subnet_id: str) -> str:
    ec2 = ctx.client("ec2")
    subnet = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]
    network = ipaddress.ip_network(subnet["CidrBlock"])
    hosts = list(network.hosts())
    idx = min(len(hosts) - 1, 100)
    return str(hosts[idx])


def _get_alb_network(ctx) -> tuple[str, list[str], str | None]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, dict] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s)
    chosen = list(by_az.values())[:2]
    if len(chosen) < 2:
        raise AssertionError("need subnets in at least 2 distinct AZs to create a load balancer")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"] if sgs else None
    return vpc_id, [s["SubnetId"] for s in chosen], sg_id


def _alb_name(ctx, tag: str) -> str:
    return ctx.unique_name(f"sim2real-{tag}-")[:32].rstrip("-")


def _resource_tags() -> list[dict[str, str]]:
    return [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real:prefix", "Value": "sim2real-vttl3"},
    ]


def _create_alb(ctx) -> tuple[str, str, list[str], str | None]:
    elbv2 = ctx.client("elbv2")
    vpc_id, subnet_ids, sg_id = _get_alb_network(ctx)
    kwargs: dict[str, Any] = dict(
        Name=_alb_name(ctx, "vttl3"),
        Subnets=subnet_ids,
        Type="application",
        Scheme="internet-facing",
        Tags=_resource_tags(),
    )
    if sg_id:
        kwargs["SecurityGroups"] = [sg_id]
    lb = elbv2.create_load_balancer(**kwargs)["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))
    return lb_arn, vpc_id, subnet_ids, sg_id


def _wait_for_lb_active(ctx, lb_arn: str, timeout_s: float = 240.0) -> None:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        lb = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
        last = lb["State"]["Code"]
        if last == "active":
            return
        if last == "failed":
            raise AssertionError(f"load balancer entered 'failed' state: {lb['State']}")
        time.sleep(5)
    raise AssertionError(
        f"load balancer did not become active within {timeout_s}s (last state={last})"
    )


def _create_target_group(ctx, vpc_id: str, **overrides) -> str:
    elbv2 = ctx.client("elbv2")
    kwargs: dict[str, Any] = dict(
        Name=_alb_name(ctx, "tg3"),
        Protocol="HTTP",
        Port=80,
        VpcId=vpc_id,
        TargetType="ip",
        HealthCheckProtocol="HTTP",
        HealthCheckPath="/",
        HealthCheckIntervalSeconds=5,
        HealthCheckTimeoutSeconds=2,
        HealthyThresholdCount=2,
        UnhealthyThresholdCount=2,
        Tags=_resource_tags(),
    )
    kwargs.update(overrides)
    tg = elbv2.create_target_group(**kwargs)["TargetGroups"][0]
    tg_arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))
    return tg_arn


def _create_listener_forwarding(ctx, lb_arn: str, tg_arn: str, port: int = 80) -> str:
    elbv2 = ctx.client("elbv2")
    listener = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTP",
        Port=port,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
        Tags=_resource_tags(),
    )["Listeners"][0]
    listener_arn = listener["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))
    return listener_arn



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
