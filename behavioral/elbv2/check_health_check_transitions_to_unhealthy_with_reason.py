"""health-check-transitions-to-unhealthy-with-reason."""
from __future__ import annotations

import ipaddress
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "health-check-transitions-to-unhealthy-with-reason"
GROUP = 'target-registration'
SERVICES = ['elbv2']

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

_INTERVAL_S = 5
_UNHEALTHY_THRESHOLD = 2


def _clamp_name(name, maxlen=32):
    return name[:maxlen].rstrip("-")


def _retry_throttled(fn, attempts=5):
    delays = [3, 6, 12, 24, 30]
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            last = exc
            time.sleep(delays[min(i, len(delays) - 1)])
    raise last


def _error(fn):
    """Return (code, message) of the ClientError fn raises; raise AssertionError if it succeeds."""
    delays = [3, 6, 12, 24, 30]
    for i in range(5):
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") not in _THROTTLE_CODES:
                return err.get("Code"), err.get("Message")
            time.sleep(delays[i])
            continue
        raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")
    raise AssertionError(f"still throttled after {len(delays)} retries")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=2.0, description="condition",
                ctx=None):
    if ctx is not None:
        timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s:.0f}s. Last result: {last!r}")


def _default_vpc_and_subnets(ctx, num_subnets=2):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in this region to place an ELBv2 load balancer in")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
    ])["Subnets"]
    per_az = {}
    for sub in sorted(subnets, key=lambda s: s["SubnetId"]):
        per_az.setdefault(sub["AvailabilityZone"], sub)
    chosen = [per_az[az] for az in sorted(per_az)][:num_subnets]
    if len(chosen) < num_subnets:
        raise AssertionError(
            f"shared network VPC {vpc_id} exposes {len(chosen)} AZ subnets, need {num_subnets}"
        )
    return vpc_id, chosen


def _unused_ip_in(subnet):
    """A high host address inside the subnet CIDR — inside the VPC, nothing listening."""
    net = ipaddress.ip_network(subnet["CidrBlock"])
    return str(net.broadcast_address - 3)


def _create_load_balancer(ctx, subnet_ids, **kwargs):
    """Billable resource: waited teardown registered AT CREATION (cleanups run LIFO)."""
    elb = ctx.client("elbv2")
    name = _clamp_name(kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-lb-"))
    params = dict(
        Name=name, Subnets=subnet_ids, Type="application",
        Scheme="internal", Tags=list(_TAGS),
    )
    params.update(kwargs)
    lb = _retry_throttled(lambda: elb.create_load_balancer(**params))["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]

    def _drop_lb():
        try:
            elb.delete_load_balancer(LoadBalancerArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                raise
            return
        for _ in range(90):
            try:
                elb.describe_load_balancers(LoadBalancerArns=[arn])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                    raise
                return
            time.sleep(2)

    ctx.on_cleanup(_drop_lb)
    return lb


def _wait_for_lb_active(ctx, lb_arn, timeout_s=600):
    elb = ctx.client("elbv2")
    lb = _poll_until(
        lambda: elb.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0],
        lambda x: x["State"]["Code"] in ("active", "active_impaired", "failed"),
        timeout_s=timeout_s, interval_s=1.0, ctx=ctx,
        description="load balancer reaching a terminal provisioning state",
    )
    assert lb["State"]["Code"] == "active", f"load balancer state {lb['State']!r}, expected active"
    return lb


def _create_target_group(ctx, **kwargs):
    elb = ctx.client("elbv2")
    name = _clamp_name(kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-tg-"))
    params = dict(Name=name, Tags=list(_TAGS))
    params.update(kwargs)
    tg = _retry_throttled(lambda: elb.create_target_group(**params))["TargetGroups"][0]
    arn = tg["TargetGroupArn"]

    def _drop_tg():
        # A target group stays ResourceInUse until the listener forwarding to it is gone.
        deadline = time.monotonic() + 120.0
        while True:
            try:
                elb.delete_target_group(TargetGroupArn=arn)
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "TargetGroupNotFound":
                    return
                if code != "ResourceInUse" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_drop_tg)
    return tg


def _create_listener(ctx, lb_arn, **kwargs):
    elb = ctx.client("elbv2")
    params = dict(LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80)
    params.update(kwargs)
    listener = _retry_throttled(lambda: elb.create_listener(**params))["Listeners"][0]
    arn = listener["ListenerArn"]
    ctx.on_cleanup(lambda: elb.delete_listener(ListenerArn=arn))
    return listener


def _target_health(ctx, tg_arn, target):
    descs = ctx.client("elbv2").describe_target_health(
        TargetGroupArn=tg_arn, Targets=[target],
    )["TargetHealthDescriptions"]
    if not descs:
        return {}
    return descs[0].get("TargetHealth") or {}


# timing:real-time — schedule: 10 s https://docs.aws.amazon.com/elasticloadbalancing/latest/application/target-group-health-checks.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control",
      "timing:real-time")
def run(ctx) -> None:
    """An in-VPC IP with nothing listening goes unused -> initial -> unhealthy with the right
    Reason codes, no faster than threshold x interval; disabling health checks is rejected.
    """
    elb = ctx.client("elbv2")
    vpc_id, subnets = _default_vpc_and_subnets(ctx)
    subnet_ids = [s["SubnetId"] for s in subnets]

    tg = _create_target_group(
        ctx, TargetType="ip", Protocol="HTTP", Port=80, VpcId=vpc_id,
        HealthCheckProtocol="HTTP", HealthCheckPort="80", HealthCheckPath="/",
        HealthCheckIntervalSeconds=_INTERVAL_S, HealthCheckTimeoutSeconds=2,
        HealthyThresholdCount=2, UnhealthyThresholdCount=_UNHEALTHY_THRESHOLD,
        Matcher={"HttpCode": "200"},
    )
    tg_arn = tg["TargetGroupArn"]
    assert tg["HealthCheckIntervalSeconds"] == _INTERVAL_S, tg
    assert tg["UnhealthyThresholdCount"] == _UNHEALTHY_THRESHOLD, tg
    assert tg.get("HealthCheckEnabled") is True, tg

    # Positive control for (e): this target group accepts other ModifyTargetGroup changes.
    # Timeout does not affect the threshold x interval math in (d).
    _retry_throttled(lambda: elb.modify_target_group(
        TargetGroupArn=tg_arn, HealthCheckTimeoutSeconds=3,
    ))
    control = elb.describe_target_groups(TargetGroupArns=[tg_arn])["TargetGroups"][0]
    assert control["HealthCheckTimeoutSeconds"] == 3, control

    target = {"Id": _unused_ip_in(subnets[0]), "Port": 80}
    _retry_throttled(lambda: elb.register_targets(TargetGroupArn=tg_arn, Targets=[target]))

    # (a) No load balancer => the health checker does not run.
    unattached = _poll_until(
        lambda: _target_health(ctx, tg_arn, target),
        lambda h: h.get("State") == "unused",
        timeout_s=90, interval_s=1.0, ctx=ctx,
        description="target in an unattached target group reporting state=unused",
    )
    assert unattached.get("Reason") == "Target.NotInUse", unattached

    lb = _create_load_balancer(ctx, subnet_ids)
    _wait_for_lb_active(ctx, lb["LoadBalancerArn"])
    _create_listener(
        ctx, lb["LoadBalancerArn"], Port=80, Protocol="HTTP",
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )
    attached_at = time.monotonic()

    # (b) Attaching starts the machine in `initial`, not straight at a verdict.
    first = _poll_until(
        lambda: _target_health(ctx, tg_arn, target),
        lambda h: h.get("State") not in (None, "unused"),
        timeout_s=180, interval_s=1.0, ctx=ctx,
        description="target leaving state=unused once its group is attached to a listener",
    )
    assert first.get("State") == "initial", (
        f"first post-attach health state was {first.get('State')!r} (reason "
        f"{first.get('Reason')!r}); real ELBv2 starts at 'initial'"
    )
    assert first.get("Reason") in ("Elb.RegistrationInProgress", "Elb.InitialHealthChecking"), first

    # (c) It converges to `unhealthy` with a target-side reason and a description.
    final = _poll_until(
        lambda: _target_health(ctx, tg_arn, target),
        lambda h: h.get("State") in ("unhealthy", "healthy", "unavailable"),
        timeout_s=480, interval_s=1.0, ctx=ctx,
        description="target converging to a terminal health verdict",
    )
    elapsed = time.monotonic() - attached_at
    assert final.get("State") == "unhealthy", (
        f"an in-VPC IP with nothing listening reported {final!r}; expected 'unhealthy'"
    )
    assert final.get("Reason") in ("Target.Timeout", "Target.FailedHealthChecks"), final
    assert final.get("Description"), f"unhealthy verdict with no Description: {final!r}"

    # (d) Thresholds are real: the load balancer declares a target unhealthy only after
    #     UnhealthyThresholdCount consecutive failed checks, one per HealthCheckIntervalSeconds.
    min_s = _UNHEALTHY_THRESHOLD * _INTERVAL_S
    assert elapsed >= min_s - 5, (
        f"declared unhealthy after {elapsed:.1f}s but UnhealthyThresholdCount"
        f"={_UNHEALTHY_THRESHOLD} x interval={_INTERVAL_S}s requires >= {min_s}s"
    )

    # (e) Health checks cannot be disabled on an ALB-attached ip target group, and the
    #     rejected attempt must not perturb the health state.
    code, message = _error(lambda: elb.modify_target_group(
        TargetGroupArn=tg_arn, HealthCheckEnabled=False,
    ))
    assert code == "InvalidConfigurationRequest", (
        f"disabling health checks on an ALB-attached ip target group returned {code!r}; "
        "real ELBv2 rejects it"
    )
    expected = "Health check enabled must be true for target groups with target type 'ip'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    described = elb.describe_target_groups(TargetGroupArns=[tg_arn])["TargetGroups"][0]
    assert described.get("HealthCheckEnabled") is True, described
    assert _target_health(ctx, tg_arn, target).get("State") == "unhealthy", (
        "rejected ModifyTargetGroup changed the target health state"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
