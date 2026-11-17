"""create-gateway-rule-priority-out-of-range-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-gateway-rule-priority-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agentcore-control", "iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateGatewayRule with priority 1,000,001 (maximum 1,000,000) is refused with
    ValidationException and the exact constraint message, creating no rule; a priority of 1 is
    accepted and reaches ACTIVE."""
    control = ctx.client("bedrock-agentcore-control")
    role_arn = _create_role(ctx)
    gateway_id = _create_gateway(ctx, control, role_arn)
    target_name = _create_target(ctx, control, gateway_id)
    action = [{"routeToTarget": {"staticRoute": {"targetName": target_name}}}]

    code, message = _error(
        lambda: control.create_gateway_rule(gatewayIdentifier=gateway_id, priority=1_000_001, actions=action)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        "1 validation error detected: Value '1000001' at 'priority' failed to satisfy constraint: "
        "Member must have value less than or equal to 1000000"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    existing = control.list_gateway_rules(gatewayIdentifier=gateway_id)
    assert existing["gatewayRules"] == [], (
        f"an over-range priority should not have created a rule, got {existing['gatewayRules']!r}"
    )

    created = control.create_gateway_rule(gatewayIdentifier=gateway_id, priority=1, actions=action)
    rule_id = created["ruleId"]
    ctx.on_cleanup(
        lambda: _delete_ignore_not_found(control.delete_gateway_rule, gatewayIdentifier=gateway_id, ruleId=rule_id)
    )
    active = _poll_until(
        lambda: control.get_gateway_rule(gatewayIdentifier=gateway_id, ruleId=rule_id),
        lambda r: r["status"] == "ACTIVE",
        timeout_s=180.0,
    )
    assert active["priority"] == 1, f"expected the in-bounds rule priority 1, got {active['priority']!r}"


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


def _create_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-gwrulepri-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "bedrock-agentcore.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_gateway(ctx, control, role_arn: str) -> str:
    gw_name = ctx.unique_name("sim2real-gwrulepri-gw-")
    gw = control.create_gateway(name=gw_name, roleArn=role_arn, authorizerType="AWS_IAM")
    gateway_id = gw["gatewayId"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(control, gateway_id))
    ready = _poll_until(
        lambda: control.get_gateway(gatewayIdentifier=gateway_id),
        lambda r: r["status"] in ("READY", "FAILED"),
        timeout_s=180.0,
    )
    assert ready["status"] == "READY", f"gateway failed to provision: {ready}"
    return gateway_id


def _create_target(ctx, control, gateway_id: str) -> str:
    target_name = ctx.unique_name("sim2real-gwrulepri-tgt-")
    target_config = {
        "http": {"passthrough": {"endpoint": "https://example.com/mcp", "protocolType": "CUSTOM"}}
    }
    target = control.create_gateway_target(
        gatewayIdentifier=gateway_id, name=target_name, targetConfiguration=target_config
    )
    target_id = target["targetId"]
    ready = _poll_until(
        lambda: control.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id),
        lambda r: r["status"] in ("READY", "FAILED"),
        timeout_s=120.0,
    )
    assert ready["status"] == "READY", f"gateway target failed to provision: {ready}"
    return target_name


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; AssertionError if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _delete_ignore_not_found(delete_fn, **kwargs) -> None:
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
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
