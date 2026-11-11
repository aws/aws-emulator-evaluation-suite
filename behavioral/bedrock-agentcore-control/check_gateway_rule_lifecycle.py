"""gateway-rule-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gateway-rule-lifecycle"
GROUP = "state"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGatewayRule reaches ACTIVE and routes to the named target;
    UpdateGatewayRule changes the priority; DeleteGatewayRule removes it."""
    control = ctx.client("bedrock-agentcore-control")
    role_arn = _create_gateway_role(ctx)

    gw = control.create_gateway(
        name=ctx.unique_name("sim2real-gw-rule-"), roleArn=role_arn, authorizerType="AWS_IAM"
    )
    gateway_id = gw["gatewayId"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(control, gateway_id))
    _poll_until(
        lambda: control.get_gateway(gatewayIdentifier=gateway_id),
        lambda g: g["status"] in ("READY", "FAILED"),
        timeout_s=180,
        interval_s=5,
    )

    target_name = ctx.unique_name("sim2real-rule-target-")
    target = control.create_gateway_target(
        gatewayIdentifier=gateway_id,
        name=target_name,
        targetConfiguration={
            "http": {"passthrough": {"endpoint": "https://example.com", "protocolType": "CUSTOM"}}
        },
        credentialProviderConfigurations=[
            {
                "credentialProviderType": "GATEWAY_IAM_ROLE",
                "credentialProvider": {
                    "iamCredentialProvider": {"service": "execute-api"}
                },
            }
        ],
    )
    target_id = target["targetId"]
    _poll_until(
        lambda: control.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id),
        lambda t: t["status"] in ("READY", "FAILED"),
        timeout_s=120,
        interval_s=4,
    )

    create_resp = control.create_gateway_rule(
        gatewayIdentifier=gateway_id,
        priority=100,
        actions=[{"routeToTarget": {"staticRoute": {"targetName": target_name}}}],
    )
    rule_id = create_resp["ruleId"]
    ctx.on_cleanup(
        lambda: _safe_delete(
            lambda: control.delete_gateway_rule(gatewayIdentifier=gateway_id, ruleId=rule_id)
        )
    )

    active = _poll_until(
        lambda: control.get_gateway_rule(gatewayIdentifier=gateway_id, ruleId=rule_id),
        lambda r: r["status"] == "ACTIVE",
        timeout_s=90,
        interval_s=3,
    )
    assert active["priority"] == 100
    assert active["actions"][0]["routeToTarget"]["staticRoute"]["targetName"] == target_name

    control.update_gateway_rule(gatewayIdentifier=gateway_id, ruleId=rule_id, priority=250)
    updated = _poll_until(
        lambda: control.get_gateway_rule(gatewayIdentifier=gateway_id, ruleId=rule_id),
        lambda r: r["status"] == "ACTIVE" and r["priority"] == 250,
        timeout_s=90,
        interval_s=3,
    )
    assert updated["priority"] == 250

    control.delete_gateway_rule(gatewayIdentifier=gateway_id, ruleId=rule_id)
    code, message = _wait_rejected(
        lambda: control.get_gateway_rule(gatewayIdentifier=gateway_id, ruleId=rule_id),
        timeout_s=90,
        interval_s=3,
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"GatewayRule {rule_id} not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
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
