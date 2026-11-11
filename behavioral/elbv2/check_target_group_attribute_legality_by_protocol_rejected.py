"""target-group-attribute-legality-by-protocol-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "target-group-attribute-legality-by-protocol-rejected"
GROUP = 'overly-permissive'
SERVICES = ['elbv2']

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


def _error_code(fn, *, why="this call"):
    """Return (ClientError code, message). An unexpected success raises immediately: accepting
    input AWS refuses must fail as that, not as a code mismatch via a falsy sentinel."""
    delays = [3, 6, 12, 24, 30]
    for i in range(5):
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code, message = err.get("Code"), err.get("Message", "")
            if code not in _THROTTLE_CODES:
                return code, message
            time.sleep(delays[i])
            continue
        raise AssertionError(
            f"{why}: expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
        )
    raise AssertionError(f"{why}: exhausted retries on throttling without a definitive answer")


def _default_vpc(ctx):
    """Create-or-adopt: use the run's shared network if one exists, otherwise create a
    throwaway VPC of our own (target-type-ip target groups need only a VpcId, no subnets)."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        return vpcs[0]["VpcId"]
    vpc = ec2.create_vpc(
        CidrBlock="10.104.0.0/16",
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": list(_TAGS) + [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}],
        }],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    return vpc_id


def _create_target_group(ctx, **kwargs):
    """Target groups are not billable on their own, but teardown is still registered
    AT CREATION so a mid-check failure cannot leak them (cleanups run LIFO)."""
    elb = ctx.client("elbv2")
    name = _clamp_name(kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-tg-"))
    params = dict(Name=name, Tags=list(_TAGS))
    params.update(kwargs)
    tg = _retry_throttled(lambda: elb.create_target_group(**params))["TargetGroups"][0]
    arn = tg["TargetGroupArn"]

    def _drop_tg():
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


def _tg_attrs(ctx, tg_arn):
    resp = ctx.client("elbv2").describe_target_group_attributes(TargetGroupArn=tg_arn)
    return {a["Key"]: a["Value"] for a in resp["Attributes"]}


def _set_tg_attrs(ctx, tg_arn, pairs):
    """Apply attributes and assert every one of them round-trips."""
    elb = ctx.client("elbv2")
    attrs = [{"Key": k, "Value": v} for k, v in pairs.items()]
    _retry_throttled(lambda: elb.modify_target_group_attributes(
        TargetGroupArn=tg_arn, Attributes=attrs,
    ))
    stored = _tg_attrs(ctx, tg_arn)
    for key, value in pairs.items():
        assert stored.get(key) == value, (
            f"legal attribute {key}={value!r} did not round-trip: {stored.get(key)!r}"
        )
    return stored


def _reject_tg_attrs(ctx, tg_arn, pairs, *, why, code_is=None, message_is=None):
    """Assert the modify is rejected (with `code_is` and exactly `message_is` when given) and that
    NOTHING in the batch was applied."""
    elb = ctx.client("elbv2")
    before = _tg_attrs(ctx, tg_arn)
    attrs = [{"Key": k, "Value": v} for k, v in pairs.items()]
    code, message = _error_code(lambda: elb.modify_target_group_attributes(
        TargetGroupArn=tg_arn, Attributes=attrs,
    ), why=why)
    assert code in _REJECTION_CODES, (
        f"{why}: ModifyTargetGroupAttributes({pairs!r}) returned {code!r} ({message!r}), "
        f"expected one of {_REJECTION_CODES}"
    )
    if code_is is not None:
        assert code == code_is, (
            f"{why}: expected error code {code_is!r}, got {code!r} ({message!r})"
        )
    if message_is is not None:
        assert message == message_is, (
            f"{why}: expected the refusal to explain itself with {message_is!r}, got {message!r}"
        )
    after = _tg_attrs(ctx, tg_arn)
    for key in pairs:
        assert after.get(key) == before.get(key), (
            f"{why}: rejected call still changed {key} from {before.get(key)!r} "
            f"to {after.get(key)!r}"
        )
    return after


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Target group attributes are legal per protocol: each key works on the protocol that owns it
    and is rejected on the other, some legal pairs are mutually exclusive, and a rejected batch
    applies nothing."""
    vpc_id = _default_vpc(ctx)

    http_tg = _create_target_group(
        ctx, TargetType="ip", Protocol="HTTP", Port=80, VpcId=vpc_id,
    )
    tcp_tg = _create_target_group(
        ctx, TargetType="ip", Protocol="TCP", Port=80, VpcId=vpc_id,
    )
    lambda_tg = _create_target_group(ctx, TargetType="lambda")
    http_arn = http_tg["TargetGroupArn"]
    tcp_arn = tcp_tg["TargetGroupArn"]
    lambda_arn = lambda_tg["TargetGroupArn"]

    # Defaults are protocol-dependent.
    http_defaults = _tg_attrs(ctx, http_arn)
    tcp_defaults = _tg_attrs(ctx, tcp_arn)
    lambda_defaults = _tg_attrs(ctx, lambda_arn)
    assert http_defaults.get("stickiness.type") == "lb_cookie", http_defaults
    assert tcp_defaults.get("stickiness.type") == "source_ip", tcp_defaults
    assert http_defaults.get("load_balancing.algorithm.type") == "round_robin", http_defaults
    assert "slow_start.duration_seconds" in http_defaults, sorted(http_defaults)
    assert "slow_start.duration_seconds" not in tcp_defaults, sorted(tcp_defaults)
    assert "proxy_protocol_v2.enabled" in tcp_defaults, sorted(tcp_defaults)
    assert "proxy_protocol_v2.enabled" not in http_defaults, sorted(http_defaults)
    assert lambda_defaults.get("lambda.multi_value_headers.enabled") == "false", lambda_defaults
    assert "stickiness.type" not in lambda_defaults, sorted(lambda_defaults)

    # --- HTTP group: HTTP-only keys work ---
    # slow_start is set while the algorithm is still the default round_robin, deliberately:
    # ELBv2 refuses slow start together with least_outstanding_requests (see the mutual-exclusion
    # block below), so the two cannot ride in one batch.
    _set_tg_attrs(ctx, http_arn, {
        "stickiness.enabled": "true",
        "stickiness.type": "lb_cookie",
        "stickiness.lb_cookie.duration_seconds": "600",
        "slow_start.duration_seconds": "60",
    })

    # --- Some COMBINATIONS of individually legal keys are refused. Each refusal is followed by
    # the state change that makes the same call legal, so it is attributable to the combination.
    _reject_tg_attrs(
        ctx, http_arn, {"load_balancing.algorithm.type": "least_outstanding_requests"},
        why="least_outstanding_requests while slow start is enabled",
        code_is="InvalidConfigurationRequest",
        message_is=(
            "You cannot enable both slow start and least "
            "outstanding requests algorithm on a target group"
        ),
    )
    # Disable slow start and the identical call is accepted.
    _set_tg_attrs(ctx, http_arn, {"slow_start.duration_seconds": "0"})
    _set_tg_attrs(ctx, http_arn, {"load_balancing.algorithm.type": "least_outstanding_requests"})
    # ...and now the pair is refused from the other side.
    _reject_tg_attrs(
        ctx, http_arn, {"slow_start.duration_seconds": "60"},
        why="slow start while the algorithm is least_outstanding_requests",
        code_is="InvalidConfigurationRequest",
        message_is=(
            "You cannot enable both slow start and least "
            "outstanding requests algorithm on a target group"
        ),
    )
    # A second, distinct mutual exclusion with its own message: weighted_random vs stickiness.
    _reject_tg_attrs(
        ctx, http_arn, {"load_balancing.algorithm.type": "weighted_random"},
        why="weighted_random while stickiness is enabled",
        code_is="InvalidConfigurationRequest",
        message_is=(
            "You cannot have both stickiness and weighted "
            "random algorithm enabled on the same target group."
        ),
    )
    # Turning stickiness off makes weighted_random legal, then restore the sticky LOR baseline
    # the rest of the check asserts against.
    _set_tg_attrs(ctx, http_arn, {"stickiness.enabled": "false"})
    _set_tg_attrs(ctx, http_arn, {"load_balancing.algorithm.type": "weighted_random"})
    _set_tg_attrs(ctx, http_arn, {
        "load_balancing.algorithm.type": "least_outstanding_requests",
        "stickiness.enabled": "true",
    })

    # --- HTTP group: TCP-only / lambda-only keys are refused ---
    _reject_tg_attrs(
        ctx, http_arn, {"stickiness.type": "source_ip"},
        why="stickiness.type=source_ip is NLB-only",
        code_is="InvalidConfigurationRequest",
        message_is=(
            "Stickiness type 'source_ip' is not supported "
            "for target groups with the HTTP protocol"
        ),
    )
    _reject_tg_attrs(
        ctx, http_arn, {"preserve_client_ip.enabled": "true"},
        why="preserve_client_ip.enabled is NLB-only",
        code_is="InvalidConfigurationRequest",
        message_is=(
            "A target group with HTTP protocol does not "
            "support the attribute preserve_client_ip.enabled"
        ),
    )
    _reject_tg_attrs(
        ctx, http_arn, {"proxy_protocol_v2.enabled": "true"},
        why="proxy_protocol_v2.enabled is NLB-only",
        code_is="InvalidConfigurationRequest",
        message_is=(
            "A target group with HTTP protocol does not "
            "support the attribute proxy_protocol_v2.enabled"
        ),
    )
    _reject_tg_attrs(
        ctx, http_arn, {"lambda.multi_value_headers.enabled": "true"},
        why="lambda.multi_value_headers.enabled is lambda-target-only",
        code_is="InvalidConfigurationRequest",
        message_is=(
            "A target group with HTTP protocol does not support "
            "the attribute lambda.headers.multiple_values.enabled"
        ),
    )

    # --- TCP group: TCP-only keys work ---
    _set_tg_attrs(ctx, tcp_arn, {
        "preserve_client_ip.enabled": "false",
        "proxy_protocol_v2.enabled": "true",
        "deregistration_delay.timeout_seconds": "120",
    })

    # --- TCP group: HTTP-only keys are refused ---
    _reject_tg_attrs(
        ctx, tcp_arn, {"stickiness.type": "lb_cookie"},
        why="stickiness.type=lb_cookie is ALB-only",
        code_is="InvalidConfigurationRequest",
        message_is=(
            "Stickiness type 'lb_cookie' is not supported "
            "for target groups with the TCP protocol"
        ),
    )
    _reject_tg_attrs(
        ctx, tcp_arn, {"load_balancing.algorithm.type": "least_outstanding_requests"},
        why="least_outstanding_requests is ALB-only",
    )
    _reject_tg_attrs(
        ctx, tcp_arn, {"slow_start.duration_seconds": "60"},
        why="slow_start.duration_seconds is ALB-only",
        code_is="InvalidConfigurationRequest",
        message_is=(
            "A target group with TCP protocol does not "
            "support the attribute slow_start.duration_seconds"
        ),
    )

    # --- Batch atomicity: one illegal key rejects the whole call ---
    _reject_tg_attrs(
        ctx, tcp_arn, {
            "deregistration_delay.timeout_seconds": "45",
            "slow_start.duration_seconds": "30",
        },
        why="a batch mixing a legal NLB key with an ALB-only key",
        code_is="InvalidConfigurationRequest",
        message_is=(
            "A target group with TCP protocol does not "
            "support the attribute slow_start.duration_seconds"
        ),
    )
    assert _tg_attrs(ctx, tcp_arn).get("deregistration_delay.timeout_seconds") == "120", (
        "the legal half of a rejected attribute batch was applied anyway"
    )

    # --- Value-level validation, not just key legality ---
    _reject_tg_attrs(
        ctx, http_arn, {"stickiness.type": "sim2real-not-a-stickiness-type"},
        why="an unknown stickiness.type value",
        code_is="ValidationError",
        message_is="'Stickiness type' must be one of [app_cookie, lb_cookie, source_ip]",
    )
    _reject_tg_attrs(
        ctx, http_arn, {"load_balancing.algorithm.type": "sim2real-not-an-algorithm"},
        why="an unknown load_balancing.algorithm.type value",
        code_is="ValidationError",
        message_is=(
            "'Load balancer algorithm' must be one of [round_robin, "
            "weighted_random, least_outstanding_requests]"
        ),
    )
    _reject_tg_attrs(
        ctx, http_arn, {"deregistration_delay.timeout_seconds": "99999"},
        why="deregistration_delay.timeout_seconds above the documented maximum of 3600",
        code_is="ValidationError",
        message_is=(
            "'deregistration_delay.timeout_seconds' value "
            "'99999' must be between '0-3600' inclusive"
        ),
    )
    _reject_tg_attrs(
        ctx, http_arn, {"sim2real.not.a.real.attribute": "1"},
        why="a wholly unknown attribute key",
        code_is="ValidationError",
        message_is="Target group attribute key 'sim2real.not.a.real.attribute' is not recognized",
    )

    # Nothing above disturbed the attributes that were legitimately applied.
    final_http = _tg_attrs(ctx, http_arn)
    assert final_http.get("stickiness.type") == "lb_cookie", final_http
    assert final_http.get("load_balancing.algorithm.type") == "least_outstanding_requests", final_http
    assert final_http.get("stickiness.lb_cookie.duration_seconds") == "600", final_http
    assert "sim2real.not.a.real.attribute" not in final_http, sorted(final_http)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
