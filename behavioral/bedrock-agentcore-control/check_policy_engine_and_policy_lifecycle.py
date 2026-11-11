"""policy-engine-and-policy-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "policy-engine-and-policy-lifecycle"
GROUP = "state"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePolicyEngine converges to ACTIVE, CreatePolicy within it converges
    to ACTIVE with the exact Cedar statement, and both can then be deleted in
    dependency order."""
    control = ctx.client("bedrock-agentcore-control")
    gateway_arn = _create_ready_gateway(ctx, control)
    cedar_statement = (
        'permit(principal, action, resource == AgentCore::Gateway::'
        f'"{gateway_arn}") '
        "when { true };"
    )
    engine_name = _no_hyphen_name(ctx, "sim2realengine")

    engine = control.create_policy_engine(name=engine_name)
    engine_id = engine["policyEngineId"]
    ctx.on_cleanup(lambda: _ac_delete_policy_engine(control, engine_id))

    engine_final = _poll_until(
        lambda: control.get_policy_engine(policyEngineId=engine_id),
        lambda e: e["status"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=90,
        interval_s=3,
    )
    assert engine_final["status"] == "ACTIVE", f"engine ended in {engine_final['status']!r}"

    policy_name = _no_hyphen_name(ctx, "sim2realpolicy")
    policy = control.create_policy(
        policyEngineId=engine_id,
        name=policy_name,
        definition={"cedar": {"statement": cedar_statement}},
        # The Cedar analyzer's schema is generated from the gateway's own tools;
        # this gateway registers none, so FAIL_ON_ANY_FINDINGS (the API default)
        # rejects even a well-formed statement at creation time.
        validationMode="IGNORE_ALL_FINDINGS",
    )
    policy_id = policy["policyId"]

    policy_final = _poll_until(
        lambda: control.get_policy(policyEngineId=engine_id, policyId=policy_id),
        lambda p: p["status"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=90,
        interval_s=3,
    )
    assert policy_final["status"] == "ACTIVE", f"policy ended in {policy_final['status']!r}"
    assert policy_final["definition"]["cedar"]["statement"] == cedar_statement, (
        f"expected statement {cedar_statement!r}, got "
        f"{policy_final['definition']['cedar']['statement']!r}"
    )
    assert policy_final["enforcementMode"] == "ACTIVE", (
        f"expected enforcementMode ACTIVE, got {policy_final['enforcementMode']!r}"
    )

    control.delete_policy(policyEngineId=engine_id, policyId=policy_id)
    _wait_gone(
        lambda: control.get_policy(policyEngineId=engine_id, policyId=policy_id),
        timeout_s=90,
        interval_s=3,
    )

    control.delete_policy_engine(policyEngineId=engine_id)
    _wait_gone(
        lambda: control.get_policy_engine(policyEngineId=engine_id),
        timeout_s=90,
        interval_s=3,
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


def _no_hyphen_name(ctx, prefix):
    raw = ctx.unique_name(f"{prefix}-")
    sanitized = "".join(ch for ch in raw if ch.isalnum() or ch == "_")
    return sanitized[:40]


def _create_ready_gateway(ctx, control):
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
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    gw = control.create_gateway(
        name=ctx.unique_name("sim2real-gw-cedar-"), roleArn=role_arn, authorizerType="AWS_IAM"
    )
    gateway_id = gw["gatewayId"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(control, gateway_id))
    _poll_until(
        lambda: control.get_gateway(gatewayIdentifier=gateway_id),
        lambda g: g["status"] in ("READY", "FAILED"),
        timeout_s=180,
        interval_s=5,
    )
    return gw["gatewayArn"]


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _wait_gone(probe, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            probe()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"resource did not disappear within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

