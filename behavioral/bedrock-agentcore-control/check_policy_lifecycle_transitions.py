"""policy-lifecycle-transitions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "policy-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Policy create->update(enforcementMode)->delete; no longer enforced post-delete."""
    client = ctx.client("bedrock-agentcore-control")
    role_arn = _create_role(ctx, "bedrock-agentcore.amazonaws.com", "sim2reals3plr")
    gateway_id, gateway_arn = _create_gateway(ctx, client, role_arn, "sim2realplrgw")
    cedar_statement = f'permit(principal, action, resource == AgentCore::Gateway::"{gateway_arn}") when {{ true }};'
    engine_name = _alnum_name(ctx, "sim2realPolEng")

    engine = client.create_policy_engine(name=engine_name, tags={"sim2real": CHECK})
    engine_id = engine["policyEngineId"]
    ctx.on_cleanup(lambda: _ac_delete_policy_engine(client, engine_id))
    _poll_until(
        lambda: client.get_policy_engine(policyEngineId=engine_id),
        lambda r: r["status"] == "ACTIVE",
        timeout_s=120.0,
    )

    policy_name = _alnum_name(ctx, "sim2realPolicy")
    created = client.create_policy(
        name=policy_name,
        definition={"cedar": {"statement": cedar_statement}},
        policyEngineId=engine_id,
        validationMode="IGNORE_ALL_FINDINGS",
        enforcementMode="LOG_ONLY",
    )
    policy_id = created["policyId"]
    assert created["enforcementMode"] == "LOG_ONLY", f"expected LOG_ONLY on create, got {created['enforcementMode']!r}"

    active = _poll_until(
        lambda: client.get_policy(policyEngineId=engine_id, policyId=policy_id),
        lambda r: r["status"] == "ACTIVE",
        timeout_s=120.0,
    )
    assert active["enforcementMode"] == "LOG_ONLY", (
        f"expected LOG_ONLY to survive the CREATING->ACTIVE transition, got {active['enforcementMode']!r}"
    )

    client.update_policy(
        policyEngineId=engine_id,
        policyId=policy_id,
        enforcementMode="ACTIVE",
        validationMode="IGNORE_ALL_FINDINGS",
    )
    enforced = _poll_until(
        lambda: client.get_policy(policyEngineId=engine_id, policyId=policy_id),
        lambda r: r["status"] in ("ACTIVE", "UPDATE_FAILED") and r.get("enforcementMode") == "ACTIVE"
        or r["status"] == "UPDATE_FAILED",
        timeout_s=120.0,
    )
    assert enforced["status"] == "ACTIVE", f"status={enforced['status']!r} reasons={enforced.get('statusReasons')!r}"
    assert enforced["enforcementMode"] == "ACTIVE", (
        f"expected enforcementMode ACTIVE after update_policy, got {enforced['enforcementMode']!r}"
    )

    client.delete_policy(policyEngineId=engine_id, policyId=policy_id)

    final_code, final_message = _error(
        lambda: client.get_policy(policyEngineId=engine_id, policyId=policy_id),
        until_code="ResourceNotFoundException",
        timeout_s=120.0,
    )
    assert final_code == "ResourceNotFoundException", (
        f"expected GetPolicy on the deleted policy to raise ResourceNotFoundException, got {final_code!r}"
    )
    expected = f"Policy with ID {policy_id} not found"
    assert final_message == expected, f"expected message {expected!r}, got {final_message!r}"

    update_dead_code, update_dead_message = _error(
        lambda: client.update_policy(
            policyEngineId=engine_id,
            policyId=policy_id,
            enforcementMode="LOG_ONLY",
            validationMode="IGNORE_ALL_FINDINGS",
        )
    )
    assert update_dead_code == "ResourceNotFoundException", (
        f"expected UpdatePolicy on the deleted policy to raise ResourceNotFoundException, got {update_dead_code!r}"
    )
    expected = f"Policy with ID {policy_id} not found"
    assert update_dead_message == expected, (
        f"expected message {expected!r}, got {update_dead_message!r}"
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


def _ac_delete_policy_engine(control, engine_id):
    """Policies first: DeletePolicyEngine is refused while the engine still holds one."""
    try:
        pages = control.get_paginator("list_policies").paginate(policyEngineId=engine_id)
        policy_ids = [p["policyId"] for page in pages for p in page.get("policies", [])]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    for policy_id in policy_ids:
        _ac_delete_and_wait(
            lambda: control.get_policy(policyEngineId=engine_id, policyId=policy_id)["status"],
            lambda: control.delete_policy(policyEngineId=engine_id, policyId=policy_id),
            what=f"policy {policy_id}",
        )
    _ac_delete_and_wait(
        lambda: control.get_policy_engine(policyEngineId=engine_id)["status"],
        lambda: control.delete_policy_engine(policyEngineId=engine_id),
        what=f"policy engine {engine_id}",
    )


def _alnum_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    return "".join(ch for ch in raw if ch.isalnum() or ch == "_")


def _gateway_name(ctx, prefix: str) -> str:
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _create_gateway(ctx, client, role_arn: str, prefix: str):
    gw_name = _gateway_name(ctx, prefix)
    gateway = client.create_gateway(
        name=gw_name, roleArn=role_arn, authorizerType="AWS_IAM", tags={"sim2real": CHECK}
    )
    gateway_id = gateway["gatewayId"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(client, gateway_id))
    active = _poll_until(
        lambda: client.get_gateway(gatewayIdentifier=gateway_id),
        lambda r: r["status"] == "READY",
        timeout_s=180.0,
    )
    return gateway_id, active["gatewayArn"]


def _error(fn, *, until_code=None, timeout_s=0.0, interval_s=3.0):
    """Return (code, message) of the ClientError fn() raises. With until_code, retry while fn()
    succeeds or raises another code, for up to timeout_s. A call that never fails raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as err:
            error = err.response["Error"]
            if until_code is None or error["Code"] == until_code or time.monotonic() >= deadline:
                return error["Code"], error.get("Message", "")
        else:
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"expected a ClientError, but the call succeeded and returned {result!r}"
                )
        time.sleep(interval_s)


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
