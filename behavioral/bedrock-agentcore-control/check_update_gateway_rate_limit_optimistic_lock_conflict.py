"""update-gateway-rate-limit-optimistic-lock-conflict."""
from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-gateway-rate-limit-optimistic-lock-conflict"
GROUP = "concurrency"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateGatewayRateLimit calls: at least one is accepted, any refusal is ConflictException with
    the exact concurrent-modification message, and the limit settles ACTIVE with one request whose rate is 20 or 30."""
    bac = ctx.client("bedrock-agentcore-control")
    role_arn = _create_agentcore_role(ctx)

    gw = bac.create_gateway(
        name=_safe_gateway_name(ctx, "sim2real-bac-gw"),
        roleArn=role_arn,
        authorizerType="AWS_IAM",
        tags={"sim2real": "update-gateway-rate-limit-optimistic-lock-conflict"},
    )
    gateway_id = gw["gatewayId"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(bac, gateway_id))
    _poll_until(
        lambda: bac.get_gateway(gatewayIdentifier=gateway_id),
        lambda r: r["status"] in ("READY", "FAILED"),
        timeout_s=180,
    )
    gw_state = bac.get_gateway(gatewayIdentifier=gateway_id)
    assert gw_state["status"] == "READY", f"gateway did not become READY: {gw_state}"

    rl = bac.create_gateway_rate_limit(
        gatewayIdentifier=gateway_id,
        dimensionKeys=["targetName"],
        entries=[{"dimensions": {"targetName": "*"}, "requests": [{"rate": 10.0, "period": "second"}]}],
    )
    rate_limit_id = rl["rateLimitId"]
    ctx.on_cleanup(
        lambda: _ac_delete_and_wait(
            lambda: bac.get_gateway_rate_limit(gatewayIdentifier=gateway_id, rateLimitId=rate_limit_id)["status"],
            lambda: bac.delete_gateway_rate_limit(gatewayIdentifier=gateway_id, rateLimitId=rate_limit_id),
            what=f"gateway rate limit {rate_limit_id}",
        )
    )
    _poll_until(
        lambda: bac.get_gateway_rate_limit(gatewayIdentifier=gateway_id, rateLimitId=rate_limit_id),
        lambda r: r["status"] == "ACTIVE",
        timeout_s=60,
    )

    def _updater(rate):
        return lambda: bac.update_gateway_rate_limit(
            gatewayIdentifier=gateway_id,
            rateLimitId=rate_limit_id,
            entries=[{"dimensions": {"targetName": "*"}, "requests": [{"rate": rate, "period": "second"}]}],
        )

    results = _race([_updater(20.0), _updater(30.0)])
    assert any(ok for ok, _ in results), f"both concurrent updaters were rejected: {results}"
    failures = [r for r in results if not r[0]]
    # Real AWS accepts both concurrent UpdateGatewayRateLimit calls (each transitions the
    # limit to UPDATING) rather than rejecting the stale one synchronously with
    # ConflictException -- the operation is serialized server-side, not optimistically
    # locked at the API boundary. Any losers must still fail with ConflictException, but
    # it is equally valid (and the commonly observed real-AWS outcome) for both writers to
    # be accepted. What must NEVER happen is a merged/corrupted final state.
    for _, (code, message) in failures:
        assert code == "ConflictException", f"expected losers to fail with ConflictException, got {code}"
        expected = f"Concurrent modification on gateway rate limit '{rate_limit_id}'. Please retry."
        assert message == expected, f"expected message {expected!r}, got {message!r}"

    final = _poll_until(
        lambda: bac.get_gateway_rate_limit(gatewayIdentifier=gateway_id, rateLimitId=rate_limit_id),
        lambda r: r["status"] == "ACTIVE",
        timeout_s=60,
    )
    final_rate = final["entries"][0]["requests"][0]["rate"]
    assert final_rate in (20.0, 30.0), f"rate limit left in inconsistent state: {final}"
    assert len(final["entries"][0]["requests"]) == 1, f"rate limit entries corrupted/merged: {final}"


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


def _safe_gateway_name(ctx, prefix):
    return ctx.unique_name(prefix + "-")


def _create_agentcore_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-bac-role-")
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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    for _ in range(15):
        try:
            iam.get_role(RoleName=role_name)
            return role_arn
        except ClientError:
            time.sleep(2)
    return role_arn


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _race(fns, timeout_s=60.0):
    results: list = [None] * len(fns)
    barrier = threading.Barrier(len(fns))

    def _wrap(i, fn):
        barrier.wait()
        try:
            return i, True, fn()
        except ClientError as exc:
            return i, False, (exc.response["Error"]["Code"], exc.response["Error"].get("Message", ""))

    with ThreadPoolExecutor(max_workers=len(fns)) as pool:
        futures = [pool.submit(_wrap, i, fn) for i, fn in enumerate(fns)]
        for fut in as_completed(futures, timeout=timeout_s):
            i, ok, value = fut.result()
            results[i] = (ok, value)
    return results


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
