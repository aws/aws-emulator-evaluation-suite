"""batch-put-gateway-rate-limits-negative-value-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-put-gateway-rate-limits-negative-value-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchPutGatewayRateLimits with a rate of -5 is refused with ValidationException and the exact constraint
    message, and creates no rate limit; an all-valid batch creates one rate limit that ListGatewayRateLimits then
    shows."""
    bac = ctx.client("bedrock-agentcore-control")
    role_arn = _create_agentcore_role(ctx)

    gw_name = _kebab(ctx, "sim2realgw", 48)
    gw = _retry_until_role_usable(
        lambda: bac.create_gateway(
            name=gw_name, roleArn=role_arn, authorizerType="AWS_IAM", tags={"sim2real": "true"}
        )
    )
    gateway_id = gw["gatewayId"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(bac, gateway_id))
    state = _poll(lambda: bac.get_gateway(gatewayIdentifier=gateway_id), lambda r: r["status"] != "CREATING")
    assert state["status"] == "READY", f"unexpected terminal gateway status {state['status']!r}"

    # A negative rate is below the modeled minimum (min=0), so a client with normal parameter
    # validation never lets it reach the wire -- a ParamValidationError there proves nothing
    # about the *service*. Route it through a client with local validation disabled so the
    # value is actually sent, and the assertion is on the service's own refusal.
    raw = ctx.client("bedrock-agentcore-control", config=Config(parameter_validation=False))
    bad_batch = [
        {
            "dimensionKeys": ["targetName"],
            "entries": [{"dimensions": {"targetName": "*"}, "requests": [{"rate": -5, "period": "second"}]}],
        }
    ]
    code, message = _error_detail(
        lambda: raw.batch_put_gateway_rate_limits(gatewayIdentifier=gateway_id, rateLimits=bad_batch)
    )
    assert code == "ValidationException", f"expected ValidationException for a negative rate, got {code!r}"
    expected_message = (
        "1 validation error detected: Value '-5.0' at "
        "'rateLimits.1.member.entries.1.member.requests.1.member.rate' failed to satisfy "
        "constraint: Member must have value greater than or equal to 0"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    existing = bac.list_gateway_rate_limits(gatewayIdentifier=gateway_id)
    assert existing["rateLimits"] == [], "a negative-valued batch should not have created anything"

    # Positive control: an all-valid batch is accepted and creates a rate limit.
    good_batch = [
        {
            "dimensionKeys": ["targetName"],
            "entries": [{"dimensions": {"targetName": "*"}, "requests": [{"rate": 50, "period": "second"}]}],
        }
    ]
    result = bac.batch_put_gateway_rate_limits(gatewayIdentifier=gateway_id, rateLimits=good_batch)
    assert len(result["rateLimits"]) == 1, f"expected exactly one created rate limit, got {result['rateLimits']!r}"
    rate_limit_id = result["rateLimits"][0]["rateLimitId"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: bac.delete_gateway_rate_limit(gatewayIdentifier=gateway_id, rateLimitId=rate_limit_id)
        )
    )

    # Terminal assertion is an independent read, not the mutating call's own response: the
    # created rate limit must actually be visible through list_gateway_rate_limits.
    after = bac.list_gateway_rate_limits(gatewayIdentifier=gateway_id)
    ids = [rl["rateLimitId"] for rl in after["rateLimits"]]
    assert rate_limit_id in ids, f"created rate limit {rate_limit_id!r} not visible in {ids!r}"


# AgentCore refuses a delete while the resource is CREATING/UPDATING or still has dependents
# (ValidationException/ConflictException), and an accepted delete completes asynchronously, so a
# teardown waits out transitional statuses and then for the resource to be gone.
_AC_TRANSITIONAL = ("CREATING", "UPDATING", "DELETING", "SYNCHRONIZING")


def _ac_delete_and_wait(get_status, delete, *, what, timeout_s=600.0, interval_s=5.0):
    """Delete once out of a transitional status, then wait for ResourceNotFound; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            last = get_status()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if last == "DELETED":
            return
        if last not in _AC_TRANSITIONAL:
            try:
                delete()
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code not in ("ConflictException", "ValidationException"):
                    raise
                last = f"{last}; delete refused: {exc}"
        if time.monotonic() >= deadline:
            raise AssertionError(f"teardown: {what} still present after {timeout_s}s ({last})")
        time.sleep(interval_s)


def _ac_delete_gateway(control, gateway_id):
    """Delete every target first (DeleteGateway is refused while one exists), then the gateway."""
    try:
        pages = control.get_paginator("list_gateway_targets").paginate(gatewayIdentifier=gateway_id)
        target_ids = [t["targetId"] for page in pages for t in page.get("items", [])]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    for target_id in target_ids:
        _ac_delete_and_wait(
            lambda: control.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id)["status"],
            lambda: control.delete_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id),
            what=f"gateway target {target_id}",
        )
    _ac_delete_and_wait(
        lambda: control.get_gateway(gatewayIdentifier=gateway_id)["status"],
        lambda: control.delete_gateway(gatewayIdentifier=gateway_id),
        what=f"gateway {gateway_id}",
    )


def _kebab(ctx, prefix: str, maxlen: int) -> str:
    raw = ctx.unique_name(prefix)
    name = re.sub(r"[^A-Za-z0-9-]", "-", raw).strip("-")
    return name[:maxlen]


def _error_detail(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises, so a
    target that accepts a value AWS refuses fails as an acceptance, not as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a validation rejection, but the call SUCCEEDED: {result!r}")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFoundException"):
            raise


def _poll(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _retry_until_role_usable(fn, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _create_agentcore_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = _kebab(ctx, "sim2real-bac-role", 64)
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
