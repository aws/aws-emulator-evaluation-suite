"""delete-policy-engine-with-policy-conflict-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-policy-engine-with-policy-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePolicyEngine is rejected while a policy still exists inside it; the
    engine remains ACTIVE, and deleting the policy first lets the same delete
    call succeed (positive control)."""
    control = ctx.client("bedrock-agentcore-control")
    gateway_arn = _create_ready_gateway(ctx, control)
    cedar_statement = (
        'permit(principal, action, resource == AgentCore::Gateway::'
        f'"{gateway_arn}") '
        "when { true };"
    )
    engine = control.create_policy_engine(
        name=_no_hyphen_name(ctx, "sim2realengine"), tags={"sim2real": CHECK}
    )
    engine_id = engine["policyEngineId"]
    ctx.on_cleanup(lambda: _ac_delete_policy_engine(control, engine_id))
    _poll_until(
        lambda: control.get_policy_engine(policyEngineId=engine_id),
        lambda e: e["status"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=90,
        interval_s=3,
    )

    policy = control.create_policy(
        policyEngineId=engine_id,
        name=_no_hyphen_name(ctx, "sim2realpolicy"),
        definition={"cedar": {"statement": cedar_statement}},
    )
    policy_id = policy["policyId"]
    _poll_until(
        lambda: control.get_policy(policyEngineId=engine_id, policyId=policy_id),
        lambda p: p["status"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=90,
        interval_s=3,
    )

    # break exactly one thing: delete the engine while a policy still lives in it.
    code, message = _error_detail(lambda: control.delete_policy_engine(policyEngineId=engine_id))
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected_message = "Policy engine still contains 1 policy and cannot be deleted"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the engine is still ACTIVE, the policy is still there.
    still_there = control.get_policy_engine(policyEngineId=engine_id)
    assert still_there["status"] == "ACTIVE", (
        f"expected policy engine to remain ACTIVE after the blocked delete, "
        f"got {still_there['status']!r}"
    )
    still_policy = control.get_policy(policyEngineId=engine_id, policyId=policy_id)
    assert still_policy["policyId"] == policy_id, (
        f"expected policy {policy_id!r} to still exist after the blocked engine delete, "
        f"got {still_policy['policyId']!r}"
    )

    # positive control: delete the policy first, then the engine delete succeeds.
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
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    gw = control.create_gateway(
        name=ctx.unique_name("sim2real-gw-cedar-"),
        roleArn=role_arn,
        authorizerType="AWS_IAM",
        tags={"sim2real": CHECK},
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


def _error_detail(fn):
    """Return (code, message) of the ClientError fn raises; a success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


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
