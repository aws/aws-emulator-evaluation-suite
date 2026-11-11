"""gateway-rate-limit-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gateway-rate-limit-lifecycle"
GROUP = "state"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGatewayRateLimit reaches ACTIVE with the configured entries;
    UpdateGatewayRateLimit changes the stored rate; DeleteGatewayRateLimit
    removes it."""
    control = ctx.client("bedrock-agentcore-control")
    role_arn = _create_gateway_role(ctx)

    gw = control.create_gateway(
        name=ctx.unique_name("sim2real-gw-ratelimit-"),
        roleArn=role_arn,
        authorizerType="AWS_IAM",
        tags={"sim2real": CHECK},
    )
    gateway_id = gw["gatewayId"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(control, gateway_id))

    create_resp = control.create_gateway_rate_limit(
        gatewayIdentifier=gateway_id,
        dimensionKeys=["targetName"],
        entries=[{"dimensions": {"targetName": "*"}, "requests": [{"rate": 100, "period": "minute"}]}],
    )
    rate_limit_id = create_resp["rateLimitId"]
    ctx.on_cleanup(
        lambda: _safe_delete(
            lambda: control.delete_gateway_rate_limit(
                gatewayIdentifier=gateway_id, rateLimitId=rate_limit_id
            )
        )
    )

    active = _poll_until(
        lambda: control.get_gateway_rate_limit(gatewayIdentifier=gateway_id, rateLimitId=rate_limit_id),
        lambda r: r["status"] == "ACTIVE",
        timeout_s=90,
        interval_s=3,
    )
    assert active["entries"][0]["requests"][0]["rate"] == 100, (
        f"expected the created entry's rate to be 100, got {active['entries'][0]['requests'][0]['rate']!r}"
    )

    control.update_gateway_rate_limit(
        gatewayIdentifier=gateway_id,
        rateLimitId=rate_limit_id,
        entries=[{"dimensions": {"targetName": "*"}, "requests": [{"rate": 50, "period": "minute"}]}],
    )
    updated = _poll_until(
        lambda: control.get_gateway_rate_limit(gatewayIdentifier=gateway_id, rateLimitId=rate_limit_id),
        lambda r: r["status"] == "ACTIVE" and r["entries"][0]["requests"][0]["rate"] == 50,
        timeout_s=90,
        interval_s=3,
    )
    assert updated["entries"][0]["requests"][0]["rate"] == 50, (
        f"expected the updated entry's rate to be 50, got {updated['entries'][0]['requests'][0]['rate']!r}"
    )

    control.delete_gateway_rate_limit(gatewayIdentifier=gateway_id, rateLimitId=rate_limit_id)

    code, message = _wait_rejected(
        lambda: control.get_gateway_rate_limit(gatewayIdentifier=gateway_id, rateLimitId=rate_limit_id),
        timeout_s=90,
        interval_s=3,
    )
    assert code == "ResourceNotFoundException", (
        f"expected an independent read of the deleted rate limit to raise ResourceNotFoundException, "
        f"got code={code!r}"
    )
    expected = f"Rate limit not found: {rate_limit_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    mutate_code, mutate_message = _error(
        lambda: control.update_gateway_rate_limit(
            gatewayIdentifier=gateway_id,
            rateLimitId=rate_limit_id,
            entries=[{"dimensions": {"targetName": "*"}, "requests": [{"rate": 10, "period": "minute"}]}],
        )
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"expected UpdateGatewayRateLimit on a deleted rate limit to raise ResourceNotFoundException, "
        f"got code={mutate_code!r}"
    )
    assert mutate_message == expected, f"expected message {expected!r}, got {mutate_message!r}"


# AgentCore refuses a delete while the resource is CREATING/UPDATING or still has dependents
# (ValidationException/ConflictException), and an accepted delete completes asynchronously. The
# runner swallows a cleanup's exception, so a bare delete in on_cleanup leaked even on PASS.
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


def _create_gateway_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-agentcore-gw-role-")
    trust_policy = {
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
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; AssertionError if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")

def _wait_rejected(fn, *, timeout_s, interval_s=3.0):
    """Retry ``fn`` until it is rejected and return its (code, message); raise on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return _error(fn)
        except AssertionError:
            if time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _safe_delete(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "ConflictException"):
            raise


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
