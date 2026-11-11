"""delete-gateway-target-in-use-by-rule-allowed."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-gateway-target-in-use-by-rule-allowed"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteGatewayTarget is accepted (DELETING) while a gateway rule routes to the target by name: the target then
    reads and re-deletes as ResourceNotFoundException with the exact message, and the rule still names it; an
    unreferenced target deletes the same way."""
    bac = ctx.client("bedrock-agentcore-control")
    role_arn = _create_agentcore_role(ctx)

    gw_name = _kebab(ctx, "sim2realgw", 48)
    gw = _retry_role_propagation(
        lambda: bac.create_gateway(name=gw_name, roleArn=role_arn, authorizerType="AWS_IAM")
    )
    gateway_id = gw["gatewayId"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(bac, gateway_id))
    _poll_until(
        lambda: bac.get_gateway(gatewayIdentifier=gateway_id), lambda r: r["status"] != "CREATING"
    )

    target_name = _kebab(ctx, "sim2realtgt", 100)
    target_config = {
        "http": {
            "passthrough": {
                "endpoint": "https://example.com/mcp",
                "protocolType": "CUSTOM",
            }
        }
    }
    tgt = bac.create_gateway_target(
        gatewayIdentifier=gateway_id, name=target_name, targetConfiguration=target_config
    )
    target_id = tgt["targetId"]
    target_ready = _poll_until(
        lambda: bac.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id),
        lambda r: r["status"] in ("READY", "FAILED"),
    )
    assert target_ready["status"] == "READY", f"target failed to provision: {target_ready}"

    rule = bac.create_gateway_rule(
        gatewayIdentifier=gateway_id,
        priority=1,
        actions=[{"routeToTarget": {"staticRoute": {"targetName": target_name}}}],
    )
    rule_id = rule["ruleId"]
    ctx.on_cleanup(
        lambda: _safe(lambda: bac.delete_gateway_rule(gatewayIdentifier=gateway_id, ruleId=rule_id))
    )
    _poll_until(
        lambda: bac.get_gateway_rule(gatewayIdentifier=gateway_id, ruleId=rule_id),
        lambda r: r["status"] not in ("CREATING",),
        timeout_s=120.0,
    )

    del_resp = bac.delete_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id)
    assert del_resp["status"] == "DELETING", (
        f"expected the in-use delete to be accepted (real AWS does not enforce "
        f"referential integrity here), got status {del_resp['status']!r}"
    )

    gone_code, gone_message = _poll_gone(
        lambda: bac.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id)
    )
    assert gone_code == "ResourceNotFoundException", (
        f"expected the deleted target to disappear, got {gone_code!r}"
    )
    expected_gone = (
        "Failed to retrieve target because it doesn't exist. Retry the request with a different resource identifier."
    )
    assert gone_message == expected_gone, f"expected message {expected_gone!r}, got {gone_message!r}"

    redelete_code, redelete_message = _error_detail(
        lambda: bac.delete_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id)
    )
    assert redelete_code == "ResourceNotFoundException", (
        f"expected a delete against the now-dead target id to fail not-found, got {redelete_code!r}"
    )
    expected_redelete = (
        "Failed to retrieve target because it doesn't exist. Retry the request with a different resource identifier."
    )
    assert redelete_message == expected_redelete, (
        f"expected message {expected_redelete!r}, got {redelete_message!r}"
    )

    rule_after = bac.get_gateway_rule(gatewayIdentifier=gateway_id, ruleId=rule_id)
    assert rule_after["status"] not in ("DELETING",), (
        f"rule should be unaffected by the dangling reference, got status {rule_after['status']!r}"
    )
    dangling_name = rule_after["actions"][0]["routeToTarget"]["staticRoute"]["targetName"]
    assert dangling_name == target_name, (
        f"rule should still literally name the now-deleted target {target_name!r}, "
        f"got {dangling_name!r}"
    )

    # Baseline: an unreferenced target deletes the same way -- no special-casing by reference.
    target_name2 = _kebab(ctx, "sim2realtgt2", 100)
    tgt2 = bac.create_gateway_target(
        gatewayIdentifier=gateway_id, name=target_name2, targetConfiguration=target_config
    )
    target_id2 = tgt2["targetId"]
    target2_ready = _poll_until(
        lambda: bac.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id2),
        lambda r: r["status"] in ("READY", "FAILED"),
    )
    assert target2_ready["status"] == "READY", f"target2 failed to provision: {target2_ready}"
    del_resp2 = bac.delete_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id2)
    assert del_resp2["status"] == "DELETING", "expected the unreferenced target delete to be accepted"
    gone2_code, gone2_message = _poll_gone(
        lambda: bac.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id2)
    )
    assert gone2_code == "ResourceNotFoundException", (
        f"expected the unreferenced target to disappear, got {gone2_code!r}"
    )
    expected_gone2 = (
        "Failed to retrieve target because it doesn't exist. Retry the request with a different resource identifier."
    )
    assert gone2_message == expected_gone2, f"expected message {expected_gone2!r}, got {gone2_message!r}"


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
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_gone(read, timeout_s=180.0, interval_s=3.0):
    """Poll read() until it raises ClientError; return (code, message). Raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = read()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
        time.sleep(interval_s)
    raise AssertionError(f"resource still readable after {timeout_s}s; last value={last!r}")


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


def _retry_role_propagation(fn, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code == "ValidationException" and "assum" in message.lower():
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    raise last_err


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
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
