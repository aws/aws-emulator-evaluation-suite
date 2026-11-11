"""listener-attributes-tcp-idle-timeout-roundtrip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "listener-attributes-tcp-idle-timeout-roundtrip"
GROUP = 'listener-lifecycle'
SERVICES = ['elbv2']

# ===== helpers =====
_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

_ATTR = "tcp.idle_timeout.seconds"


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
    """Call fn(); return its ClientError (code, message), retrying throttles. Success raises."""
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
        raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")
    raise AssertionError(f"still throttled after {len(delays)} retries")


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


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
        per_az.setdefault(sub["AvailabilityZone"], sub["SubnetId"])
    subnet_ids = [per_az[az] for az in sorted(per_az)][:num_subnets]
    if len(subnet_ids) < num_subnets:
        raise AssertionError(
            f"shared network VPC {vpc_id} exposes {len(subnet_ids)} AZ subnets, need {num_subnets}"
        )
    return vpc_id, subnet_ids


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
        timeout_s=timeout_s, interval_s=10,
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
        # A listener or deleting load balancer holds the group briefly: retry only ResourceInUse.
        deadline = time.monotonic() + 60
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


def _listener_attrs(ctx, listener_arn):
    resp = ctx.client("elbv2").describe_listener_attributes(ListenerArn=listener_arn)
    return {a["Key"]: a["Value"] for a in resp["Attributes"]}
# ===== end helpers =====


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An NLB TCP listener's tcp.idle_timeout.seconds defaults to 350, persists a modify, is
    idempotent on re-apply, and rejects out-of-range values (unmutated) and unknown keys.
    """
    elb = ctx.client("elbv2")
    vpc_id, subnet_ids = _default_vpc_and_subnets(ctx)

    lb = _create_load_balancer(ctx, subnet_ids, Type="network", Scheme="internal")
    _wait_for_lb_active(ctx, lb["LoadBalancerArn"])

    tg = _create_target_group(
        ctx, TargetType="ip", Protocol="TCP", Port=80, VpcId=vpc_id,
    )
    listener = _create_listener(
        ctx, lb["LoadBalancerArn"], Protocol="TCP", Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}],
    )
    la = listener["ListenerArn"]

    # 1. The documented default must be materialized, not an empty attribute list.
    defaults = _listener_attrs(ctx, la)
    assert _ATTR in defaults, (
        f"DescribeListenerAttributes returned {sorted(defaults)!r}; "
        f"a TCP NLB listener must expose {_ATTR}"
    )
    assert defaults[_ATTR] == "350", (
        f"{_ATTR} default is {defaults[_ATTR]!r}; real ELBv2 defaults to '350'"
    )

    # 2. A modify persists and is readable back.
    modified = _retry_throttled(lambda: elb.modify_listener_attributes(
        ListenerArn=la, Attributes=[{"Key": _ATTR, "Value": "120"}],
    ))
    echoed = {a["Key"]: a["Value"] for a in modified["Attributes"]}
    assert echoed.get(_ATTR) == "120", f"ModifyListenerAttributes echoed {echoed!r}"
    assert _listener_attrs(ctx, la).get(_ATTR) == "120", (
        "modified listener attribute did not survive a fresh DescribeListenerAttributes"
    )

    # 3. Re-applying the same value is idempotent, not an error or a reset.
    _retry_throttled(lambda: elb.modify_listener_attributes(
        ListenerArn=la, Attributes=[{"Key": _ATTR, "Value": "120"}],
    ))
    assert _listener_attrs(ctx, la).get(_ATTR) == "120", "idempotent re-apply changed the value"

    # 4. Out-of-range values (documented range 60-6000) are rejected without mutating.
    for bad in ("10", "9000"):
        code, message = _error(lambda: elb.modify_listener_attributes(
            ListenerArn=la, Attributes=[{"Key": _ATTR, "Value": bad}],
        ))
        assert code == "ValidationError", (
            f"{_ATTR}={bad} is outside the documented 60-6000 range but returned {code!r}"
        )
        expected = f"'{_ATTR}' value '{bad}' must be between '60-6000' inclusive"
        assert message == expected, f"expected message {expected!r}, got {message!r}"
        assert _listener_attrs(ctx, la).get(_ATTR) == "120", (
            f"rejected {_ATTR}={bad} still mutated the stored value"
        )

    # 5. An unknown attribute key must not be silently absorbed.
    unknown, unknown_message = _error(lambda: elb.modify_listener_attributes(
        ListenerArn=la, Attributes=[{"Key": "sim2real.not.a.real.attribute", "Value": "1"}],
    ))
    assert unknown == "ValidationError", (
        f"an unknown listener attribute key returned {unknown!r}; real ELBv2 rejects it"
    )
    expected_unknown = "Listener attribute key 'sim2real.not.a.real.attribute' is not recognized"
    assert unknown_message == expected_unknown, (
        f"expected message {expected_unknown!r}, got {unknown_message!r}"
    )
    after = _listener_attrs(ctx, la)
    assert "sim2real.not.a.real.attribute" not in after, (
        f"unknown attribute key was stored anyway: {sorted(after)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
