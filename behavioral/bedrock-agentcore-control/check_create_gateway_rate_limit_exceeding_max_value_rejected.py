"""create-gateway-rate-limit-exceeding-max-value-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-gateway-rate-limit-exceeding-max-value-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateGatewayRateLimit with rate 20,000,000 (maximum 10,000,000) is refused with ValidationException and the
    exact constraint message, creating no rate limit; a rate of 100 is created and reaches ACTIVE."""
    bac = ctx.client("bedrock-agentcore-control")
    role_arn = _create_agentcore_role(ctx)

    gw_name = _kebab(ctx, "sim2realgw", 48)
    gw = _retry_until_role_usable(
        lambda: bac.create_gateway(
            name=gw_name,
            roleArn=role_arn,
            authorizerType="AWS_IAM",
            tags={"sim2real:managed": "true", "sim2real:check": CHECK},
        )
    )
    gateway_id = gw["gatewayId"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(bac, gateway_id))
    _poll_until(lambda: bac.get_gateway(gatewayIdentifier=gateway_id), lambda r: r["status"] != "CREATING")

    over_limit_entries = [
        {"dimensions": {"targetName": "*"}, "requests": [{"rate": 20_000_000, "period": "second"}]}
    ]
    code, message = _error_detail(
        lambda: bac.create_gateway_rate_limit(
            gatewayIdentifier=gateway_id, dimensionKeys=["targetName"], entries=over_limit_entries
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        "1 validation error detected: Value '2.0E7' at 'entries.1.member.requests.1.member.rate' "
        "failed to satisfy constraint: Member must have value less than or equal to 10000000"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    existing = bac.list_gateway_rate_limits(gatewayIdentifier=gateway_id)
    assert existing["rateLimits"] == [], "an over-limit rate limit should not have been created"

    # Positive control: a value within the documented bounds is accepted, and an
    # independent read at the destination confirms it is live, not just echoed
    # back by the call that created it.
    valid_entries = [
        {"dimensions": {"targetName": "*"}, "requests": [{"rate": 100, "period": "second"}]}
    ]
    created = bac.create_gateway_rate_limit(
        gatewayIdentifier=gateway_id, dimensionKeys=["targetName"], entries=valid_entries
    )
    rate_limit_id = created["rateLimitId"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: bac.delete_gateway_rate_limit(gatewayIdentifier=gateway_id, rateLimitId=rate_limit_id)
        )
    )
    active = _poll_until(
        lambda: bac.get_gateway_rate_limit(gatewayIdentifier=gateway_id, rateLimitId=rate_limit_id),
        lambda r: r["status"] == "ACTIVE",
    )
    assert active["status"] == "ACTIVE", (
        f"expected the in-bounds rate limit to reach ACTIVE, got {active['status']!r}"
    )


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
    """Return (code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFoundException"):
            raise


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _retry_until_role_usable(fn, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_exc = exc
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
