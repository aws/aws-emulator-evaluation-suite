"""update-gateway-rule-optimistic-lock-conflict."""
from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-gateway-rule-optimistic-lock-conflict"
GROUP = "concurrency"
SERVICES = ["bedrock-agentcore-control"]
_CONFLICT_MESSAGE = (
    "Failed to update the resource due to an existing lock. This means that there was a concurrent request that updated the resource. Retry the request after the other request has completed."
)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateGatewayRule calls (priority 200 and 300) on one rule: each is applied
    or refused with ConflictException, and the rule settles on an accepted call's priority, never
    the original or a refused call's."""
    bac = ctx.client("bedrock-agentcore-control")
    role_arn = _create_agentcore_role(ctx)

    gw = bac.create_gateway(
        name=ctx.unique_name("sim2real-bac-gw-"),
        roleArn=role_arn,
        authorizerType="AWS_IAM",
    )
    gateway_id = gw["gatewayId"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(bac, gateway_id))
    _poll_until(
        lambda: bac.get_gateway(gatewayIdentifier=gateway_id),
        lambda r: r["status"] in ("READY", "FAILED"),
        timeout_s=_wait_s(ctx, 180),
    )
    gw_state = bac.get_gateway(gatewayIdentifier=gateway_id)
    assert gw_state["status"] == "READY", f"expected gateway READY, got {gw_state['status']!r}"

    bundle = bac.create_configuration_bundle(
        bundleName=_alnum_name(ctx, "sim2realbundle"),
        components={"sim2real_component": {"configuration": {"key": "v1"}}},
    )
    bundle_arn = bundle["bundleArn"]
    version_id = bundle["versionId"]
    bundle_id = bundle["bundleId"]
    ctx.on_cleanup(lambda: bac.delete_configuration_bundle(bundleId=bundle_id))

    rule = bac.create_gateway_rule(
        gatewayIdentifier=gateway_id,
        priority=100,
        actions=[{"configurationBundle": {"staticOverride": {"bundleArn": bundle_arn, "bundleVersion": version_id}}}],
    )
    rule_id = rule["ruleId"]
    ctx.on_cleanup(
        lambda: _ac_delete_and_wait(
            lambda: bac.get_gateway_rule(gatewayIdentifier=gateway_id, ruleId=rule_id)["status"],
            lambda: bac.delete_gateway_rule(gatewayIdentifier=gateway_id, ruleId=rule_id),
            what=f"gateway rule {rule_id}",
        )
    )
    _poll_until(
        lambda: bac.get_gateway_rule(gatewayIdentifier=gateway_id, ruleId=rule_id),
        lambda r: r["status"] == "ACTIVE",
        timeout_s=_wait_s(ctx, 60),
    )

    def _updater(priority):
        return lambda: bac.update_gateway_rule(gatewayIdentifier=gateway_id, ruleId=rule_id, priority=priority)

    results = _race([_updater(200), _updater(300)])
    for ok, value in results:
        if not ok:
            code, message = value
            assert code == "ConflictException", f"undocumented UpdateGatewayRule refusal: {code!r} ({message!r})"
            assert message == _CONFLICT_MESSAGE, f"ConflictException message {message!r}, expected {_CONFLICT_MESSAGE!r}"
    accepted = {p for (ok, _), p in zip(results, (200, 300)) if ok}
    assert accepted, f"both UpdateGatewayRule callers were refused: {results}"

    final = _poll_until(
        lambda: bac.get_gateway_rule(gatewayIdentifier=gateway_id, ruleId=rule_id),
        lambda r: r["status"] == "ACTIVE",
        timeout_s=_wait_s(ctx, 60),
    )
    assert final["priority"] in accepted, (
        f"rule priority {final['priority']!r} is not an accepted update {sorted(accepted)}: {final}"
    )


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


def _alnum_name(ctx, prefix):
    raw = ctx.unique_name(prefix + "-")
    return "".join(ch for ch in raw if ch.isalnum())


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


def _wait_s(ctx, cap_s):
    """cap_s, shortened so the wait ends before the runner's budget does."""
    left = ctx.time_left()
    if left is None:
        return cap_s
    return max(1.0, min(cap_s, left - 10.0))


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
            return i, False, (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=len(fns)) as pool:
        futures = [pool.submit(_wrap, i, fn) for i, fn in enumerate(fns)]
        for fut in as_completed(futures, timeout=timeout_s):
            i, ok, value = fut.result()
            results[i] = (ok, value)
    return results


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
