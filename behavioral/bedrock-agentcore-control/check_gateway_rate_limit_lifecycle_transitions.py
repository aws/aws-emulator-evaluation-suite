"""gateway-rate-limit-lifecycle-transitions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gateway-rate-limit-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GatewayRateLimit single-create and BatchPutGatewayRateLimits converge to one lifecycle."""
    client = ctx.client("bedrock-agentcore-control")
    role_arn = _create_role(ctx, "bedrock-agentcore.amazonaws.com", "sim2reals3grl")
    gateway_id = _create_gateway(ctx, client, role_arn, "sim2realgrlgw")

    created = client.create_gateway_rate_limit(
        gatewayIdentifier=gateway_id,
        dimensionKeys=["targetName"],
        entries=[{"dimensions": {"targetName": "*"}, "requests": [{"rate": 100.0, "period": "minute"}]}],
    )
    rate_limit_id = created["rateLimitId"]
    ctx.on_cleanup(
        lambda: _delete_ignore_not_found(
            client.delete_gateway_rate_limit, gatewayIdentifier=gateway_id, rateLimitId=rate_limit_id
        )
    )
    _poll_until(
        lambda: client.get_gateway_rate_limit(gatewayIdentifier=gateway_id, rateLimitId=rate_limit_id),
        lambda r: r["status"] == "ACTIVE",
        timeout_s=120.0,
    )

    client.update_gateway_rate_limit(
        gatewayIdentifier=gateway_id,
        rateLimitId=rate_limit_id,
        entries=[{"dimensions": {"targetName": "*"}, "requests": [{"rate": 250.0, "period": "minute"}]}],
    )
    updated = _poll_until(
        lambda: client.get_gateway_rate_limit(gatewayIdentifier=gateway_id, rateLimitId=rate_limit_id),
        lambda r: r["status"] == "ACTIVE" and r["entries"][0]["requests"][0]["rate"] == 250.0,
        timeout_s=120.0,
    )
    assert updated["entries"][0]["requests"][0]["rate"] == 250.0

    batch = client.batch_put_gateway_rate_limits(
        gatewayIdentifier=gateway_id,
        rateLimits=[
            {
                "dimensionKeys": ["toolName"],
                "entries": [{"dimensions": {"toolName": "*"}, "requests": [{"rate": 50.0, "period": "second"}]}],
            },
            {
                "dimensionKeys": ["qualifiedModelId"],
                "entries": [
                    {"dimensions": {"qualifiedModelId": "*"}, "connections": [{"rate": 5.0, "period": "second"}]}
                ],
            },
        ],
    )
    batch_ids = [rl["rateLimitId"] for rl in batch["rateLimits"]]
    assert len(batch_ids) == 2
    for rl_id in batch_ids:
        ctx.on_cleanup(
            lambda rid=rl_id: _delete_ignore_not_found(
                client.delete_gateway_rate_limit, gatewayIdentifier=gateway_id, rateLimitId=rid
            )
        )

    all_ids = [rate_limit_id] + batch_ids
    for rl_id in all_ids:
        settled = _poll_until(
            lambda rid=rl_id: client.get_gateway_rate_limit(gatewayIdentifier=gateway_id, rateLimitId=rid),
            lambda r: r["status"] == "ACTIVE",
            timeout_s=120.0,
        )
        assert settled["status"] == "ACTIVE"

    listed_ids = {rl["rateLimitId"] for rl in client.list_gateway_rate_limits(gatewayIdentifier=gateway_id)["rateLimits"]}
    assert set(all_ids).issubset(listed_ids)

    for rl_id in all_ids:
        client.delete_gateway_rate_limit(gatewayIdentifier=gateway_id, rateLimitId=rl_id)

    for rl_id in all_ids:
        final_code, final_message = _error(
            lambda rid=rl_id: client.get_gateway_rate_limit(gatewayIdentifier=gateway_id, rateLimitId=rid),
            timeout_s=120.0,
        )
        assert final_code == "ResourceNotFoundException", final_code
        assert final_message == f"Rate limit not found: {rl_id}", final_message


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


def _alnum_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    return "".join(ch for ch in raw if ch.isalnum() or ch == "-")


def _create_role(ctx, principal: str, prefix: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(prefix)[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _create_gateway(ctx, client, role_arn: str, prefix: str) -> str:
    gw_name = _alnum_name(ctx, prefix)
    gateway = client.create_gateway(
        name=gw_name,
        roleArn=role_arn,
        authorizerType="AWS_IAM",
        protocolType="MCP",
        tags={"sim2real-check": CHECK},
    )
    gateway_id = gateway["gatewayId"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(client, gateway_id))
    _poll_until(
        lambda: client.get_gateway(gatewayIdentifier=gateway_id),
        lambda r: r["status"] == "READY",
        timeout_s=180.0,
    )
    return gateway_id


def _error(fn, *, timeout_s=0.0, interval_s=2.0):
    """Call fn() until it is refused; return the refusal's (code, message). A call that still
    succeeds once timeout_s has passed raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError("expected the call to be refused, but it succeeded")
        time.sleep(interval_s)


def _delete_ignore_not_found(delete_fn, **kwargs) -> None:
    from botocore.exceptions import ClientError

    try:
        delete_fn(**kwargs)
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("ResourceNotFoundException", "ConflictException"):
            raise


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
