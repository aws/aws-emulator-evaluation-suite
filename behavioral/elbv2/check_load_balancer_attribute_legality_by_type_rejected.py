"""load-balancer-attribute-legality-by-type-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "load-balancer-attribute-legality-by-type-rejected"
GROUP = 'overly-permissive'
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

_REJECTION_CODES = ("ValidationError", "InvalidConfigurationRequest")


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


def _error_code(fn):
    """Return (ClientError code, message), or (None, '') when the call unexpectedly succeeded."""
    delays = [3, 6, 12, 24, 30]
    code, message = None, ""
    for i in range(5):
        try:
            fn()
            return None, ""
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code, message = err.get("Code"), err.get("Message", "")
        if code not in _THROTTLE_CODES:
            return code, message
        time.sleep(delays[i])
    return code, message


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


def _lb_attrs(ctx, lb_arn):
    resp = ctx.client("elbv2").describe_load_balancer_attributes(LoadBalancerArn=lb_arn)
    return {a["Key"]: a["Value"] for a in resp["Attributes"]}


def _set_lb_attrs(ctx, lb_arn, pairs):
    """Apply attributes and assert every one of them round-trips."""
    elb = ctx.client("elbv2")
    attrs = [{"Key": k, "Value": v} for k, v in pairs.items()]
    _retry_throttled(lambda: elb.modify_load_balancer_attributes(
        LoadBalancerArn=lb_arn, Attributes=attrs,
    ))
    stored = _lb_attrs(ctx, lb_arn)
    for key, value in pairs.items():
        assert stored.get(key) == value, (
            f"legal attribute {key}={value!r} did not round-trip: {stored.get(key)!r}"
        )
    return stored


def _reject_lb_attrs(ctx, lb_arn, pairs, *, why, code_is, message_is):
    """Assert the modify is rejected with `code_is` and exactly `message_is`, and that NOTHING in
    the batch was applied."""
    elb = ctx.client("elbv2")
    before = _lb_attrs(ctx, lb_arn)
    attrs = [{"Key": k, "Value": v} for k, v in pairs.items()]
    code, message = _error_code(lambda: elb.modify_load_balancer_attributes(
        LoadBalancerArn=lb_arn, Attributes=attrs,
    ))
    assert code in _REJECTION_CODES, (
        f"{why}: ModifyLoadBalancerAttributes({pairs!r}) returned {code!r} ({message!r}), "
        f"expected one of {_REJECTION_CODES}"
    )
    assert code == code_is, (
        f"{why}: expected error code {code_is!r}, got {code!r} ({message!r})"
    )
    assert message == message_is, (
        f"{why}: expected the refusal to explain itself with {message_is!r}, got {message!r}"
    )
    after = _lb_attrs(ctx, lb_arn)
    for key in pairs:
        assert after.get(key) == before.get(key), (
            f"{why}: rejected call still changed {key} from {before.get(key)!r} "
            f"to {after.get(key)!r}"
        )
    return after
# ===== end helpers =====


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Load balancer attributes are legal per type: an ALB rejects NLB-only keys and an NLB rejects
    ALB-only keys, a mixed batch with one illegal key applies nothing, and an ALB refuses
    ``load_balancing.cross_zone.enabled=false`` while accepting ``true``."""
    _vpc_id, subnet_ids = _default_vpc_and_subnets(ctx)

    alb = _create_load_balancer(ctx, subnet_ids, Type="application", Scheme="internal")
    nlb = _create_load_balancer(ctx, subnet_ids, Type="network", Scheme="internal")
    alb_arn = alb["LoadBalancerArn"]
    nlb_arn = nlb["LoadBalancerArn"]
    _wait_for_lb_active(ctx, alb_arn)
    _wait_for_lb_active(ctx, nlb_arn)

    # Baseline defaults differ by type, and that difference is itself an invariant.
    alb_defaults = _lb_attrs(ctx, alb_arn)
    nlb_defaults = _lb_attrs(ctx, nlb_arn)
    assert alb_defaults.get("idle_timeout.timeout_seconds") == "60", alb_defaults
    assert "idle_timeout.timeout_seconds" not in nlb_defaults, (
        f"NLB exposes the ALB-only idle_timeout attribute: {sorted(nlb_defaults)!r}"
    )
    # Cross-zone exists on both types but with OPPOSITE defaults: an ALB always balances across
    # zones, an NLB does not until asked. An emulator with one attribute-default table gets one of
    # these two wrong.
    assert alb_defaults.get("load_balancing.cross_zone.enabled") == "true", alb_defaults
    assert nlb_defaults.get("load_balancing.cross_zone.enabled") == "false", nlb_defaults

    # ALB positive: ALB-only keys are accepted and persisted.
    _set_lb_attrs(ctx, alb_arn, {
        "idle_timeout.timeout_seconds": "120",
        "routing.http2.enabled": "false",
        "deletion_protection.enabled": "false",
    })

    # ALB negative: NLB-only keys are refused, with no partial application. The message names the
    # TYPE, which is the fact under test -- the key is not unknown, it is unsupported here.
    _reject_lb_attrs(
        ctx, alb_arn, {"dns_record.client_routing_policy": "availability_zone_affinity"},
        why="dns_record.client_routing_policy is NLB-only",
        code_is="InvalidConfigurationRequest",
        message_is=(
            "Load balancer attribute key 'dns_record.client_routing_policy' is not supported "
            "on load balancers with type 'application'"
        ),
    )

    # ALB negative of a different kind: a key that IS supported but whose value is pinned by the
    # type. Disabling cross-zone on an ALB is refused...
    _reject_lb_attrs(
        ctx, alb_arn, {"load_balancing.cross_zone.enabled": "false"},
        why="cross-zone load balancing cannot be disabled on an Application Load Balancer",
        code_is="ValidationError",
        message_is=(
            "The value for 'load_balancing.cross_zone.enabled' must always be 'true' for an "
            "Application Load Balancer"
        ),
    )
    # ...while re-asserting the value it is pinned to is accepted, so the refusal above is about
    # the VALUE and not about the key being rejected on ALBs.
    _set_lb_attrs(ctx, alb_arn, {"load_balancing.cross_zone.enabled": "true"})

    # NLB positive: cross-zone is settable on an NLB.
    _set_lb_attrs(ctx, nlb_arn, {"load_balancing.cross_zone.enabled": "true"})

    # NLB negatives: ALB-only keys are refused.
    _reject_lb_attrs(
        ctx, nlb_arn, {"idle_timeout.timeout_seconds": "120"},
        why="idle_timeout.timeout_seconds is ALB-only",
        code_is="ValidationError",
        message_is="Load balancer attribute key 'idle_timeout.timeout_seconds' is not recognized",
    )
    _reject_lb_attrs(
        ctx, nlb_arn, {"routing.http2.enabled": "false"},
        why="routing.http2.enabled is ALB-only",
        code_is="ValidationError",
        message_is="Load balancer attribute key 'routing.http2.enabled' is not recognized",
    )

    # Batch atomicity: one illegal key rejects the whole call, so the legal key
    # riding along with it must NOT be applied.
    _reject_lb_attrs(
        ctx, nlb_arn, {
            "load_balancing.cross_zone.enabled": "false",
            "routing.http2.enabled": "true",
        },
        why="a batch mixing a legal NLB key with an ALB-only key",
        code_is="ValidationError",
        message_is="Load balancer attribute key 'routing.http2.enabled' is not recognized",
    )
    assert _lb_attrs(ctx, nlb_arn).get("load_balancing.cross_zone.enabled") == "true", (
        "the legal half of a rejected attribute batch was applied anyway"
    )

    # Value validation, not just key legality: out-of-range and non-boolean values.
    _reject_lb_attrs(
        ctx, alb_arn, {"idle_timeout.timeout_seconds": "0"},
        why="idle_timeout.timeout_seconds=0 is below the documented minimum of 1",
        code_is="ValidationError",
        message_is="The value of 'idle_timeout.timeout_seconds' cannot be less than 1 characters",
    )
    _reject_lb_attrs(
        ctx, alb_arn, {"routing.http2.enabled": "sim2real-not-a-boolean"},
        why="routing.http2.enabled requires a boolean",
        code_is="ValidationError",
        message_is=(
            "The value of 'routing.http2.enabled' must be 'true' or 'false', but was "
            "'sim2real-not-a-boolean'"
        ),
    )
    assert _lb_attrs(ctx, alb_arn).get("idle_timeout.timeout_seconds") == "120", (
        "a rejected value change perturbed the previously accepted idle_timeout"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
