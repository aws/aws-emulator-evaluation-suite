"""gateway-rule-lifecycle-transitions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gateway-rule-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GatewayRule create->update->delete state machine, independent of sibling rules."""
    client = ctx.client("bedrock-agentcore-control")
    sts = ctx.client("sts")
    caller_arn = sts.get_caller_identity()["Arn"]
    role_arn = _create_role(ctx, "bedrock-agentcore.amazonaws.com", "sim2reals3gru")
    gateway_id = _create_gateway(ctx, client, role_arn, "sim2realgrugw")
    bundle_arn, bundle_version = _create_bundle(ctx, client, "sim2realgrubundle")

    action = [{"configurationBundle": {"staticOverride": {"bundleArn": bundle_arn, "bundleVersion": bundle_version}}}]

    created1 = client.create_gateway_rule(
        gatewayIdentifier=gateway_id,
        priority=100,
        conditions=[{"matchPrincipals": {"anyOf": [{"iamPrincipal": {"arn": caller_arn, "operator": "StringEquals"}}]}}],
        actions=action,
        description="rule one",
    )
    rule1_id = created1["ruleId"]
    ctx.on_cleanup(
        lambda: _delete_ignore_not_found(client.delete_gateway_rule, gatewayIdentifier=gateway_id, ruleId=rule1_id)
    )
    assert created1["priority"] == 100, f"expected create echo priority 100, got {created1['priority']!r}"

    active1 = _poll_until(
        lambda: client.get_gateway_rule(gatewayIdentifier=gateway_id, ruleId=rule1_id),
        lambda r: r["status"] == "ACTIVE",
        timeout_s=120.0,
    )
    assert active1["priority"] == 100, f"expected active rule1 priority 100, got {active1['priority']!r}"

    client.update_gateway_rule(gatewayIdentifier=gateway_id, ruleId=rule1_id, priority=150, description="rule one updated")
    updated1 = _poll_until(
        lambda: client.get_gateway_rule(gatewayIdentifier=gateway_id, ruleId=rule1_id),
        lambda r: r["status"] == "ACTIVE" and r["priority"] == 150,
        timeout_s=120.0,
    )
    assert updated1["priority"] == 150, f"expected updated rule1 priority 150, got {updated1['priority']!r}"

    created2 = client.create_gateway_rule(
        gatewayIdentifier=gateway_id,
        priority=999,
        conditions=[{"matchPrincipals": {"anyOf": [{"iamPrincipal": {"arn": caller_arn, "operator": "StringEquals"}}]}}],
        actions=action,
        description="rule two",
    )
    rule2_id = created2["ruleId"]
    ctx.on_cleanup(
        lambda: _delete_ignore_not_found(client.delete_gateway_rule, gatewayIdentifier=gateway_id, ruleId=rule2_id)
    )
    _poll_until(
        lambda: client.get_gateway_rule(gatewayIdentifier=gateway_id, ruleId=rule2_id),
        lambda r: r["status"] == "ACTIVE",
        timeout_s=120.0,
    )

    client.delete_gateway_rule(gatewayIdentifier=gateway_id, ruleId=rule1_id)

    final_code, final_message = _wait_rejected(
        lambda: client.get_gateway_rule(gatewayIdentifier=gateway_id, ruleId=rule1_id), timeout_s=120.0
    )
    assert final_code == "ResourceNotFoundException", f"expected rule1 gone, got code {final_code!r}"
    expected = f"GatewayRule {rule1_id} not found"
    assert final_message == expected, f"expected message {expected!r}, got {final_message!r}"

    dead_update_code, dead_update_message = _error(
        lambda: client.update_gateway_rule(gatewayIdentifier=gateway_id, ruleId=rule1_id, priority=1)
    )
    assert dead_update_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException mutating deleted rule, got {dead_update_code!r}"
    )
    assert dead_update_message == expected, (
        f"expected message {expected!r}, got {dead_update_message!r}"
    )

    still_there = client.get_gateway_rule(gatewayIdentifier=gateway_id, ruleId=rule2_id)
    assert still_there["status"] == "ACTIVE", f"expected rule2 unaffected by rule1 delete, status={still_there['status']!r}"
    assert still_there["priority"] == 999, f"expected rule2 priority unchanged at 999, got {still_there['priority']!r}"


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


def _bundle_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    return "".join(ch for ch in raw if ch.isalnum() or ch == "_")


def _create_bundle(ctx, client, prefix: str):
    bundle_name = _bundle_name(ctx, prefix)
    created = client.create_configuration_bundle(
        bundleName=bundle_name,
        description="bundle for gateway rule routing",
        components={"sim2realComponent": {"configuration": {"setting": "v1"}}},
        tags={"sim2real": "true"},
    )
    bundle_id = created["bundleId"]
    ctx.on_cleanup(lambda: _delete_ignore_not_found(client.delete_configuration_bundle, bundleId=bundle_id))
    return created["bundleArn"], created["versionId"]


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
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _create_gateway(ctx, client, role_arn: str, prefix: str) -> str:
    gw_name = _alnum_name(ctx, prefix)
    gateway = client.create_gateway(
        name=gw_name, roleArn=role_arn, authorizerType="AWS_IAM", tags={"sim2real": "true"}
    )
    gateway_id = gateway["gatewayId"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(client, gateway_id))
    _poll_until(
        lambda: client.get_gateway(gatewayIdentifier=gateway_id),
        lambda r: r["status"] == "READY",
        timeout_s=180.0,
    )
    return gateway_id


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
