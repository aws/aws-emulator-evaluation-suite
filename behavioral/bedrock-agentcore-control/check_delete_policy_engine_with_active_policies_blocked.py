"""delete-policy-engine-with-active-policies-blocked."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-policy-engine-with-active-policies-blocked"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePolicyEngine while it holds a policy is refused with ConflictException "Policy engine still contains 1
    policy and cannot be deleted", leaving engine and policy in place; once the policy is gone the same delete
    answers DELETING and the engine then reads as not found with the exact message."""
    bac = ctx.client("bedrock-agentcore-control")
    role_arn = _create_agentcore_role(ctx)

    gw_name = _kebab(ctx, "sim2realgw", 48)
    gw = _create_gateway_with_retry(bac, name=gw_name, roleArn=role_arn, authorizerType="AWS_IAM")
    gateway_id = gw["gatewayId"]
    gateway_arn = gw["gatewayArn"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(bac, gateway_id))
    _poll(lambda: bac.get_gateway(gatewayIdentifier=gateway_id), lambda r: r["status"] != "CREATING")

    engine_name = _alnum(ctx, "sim2realPolEng", 48)
    engine = bac.create_policy_engine(name=engine_name)
    engine_id = engine["policyEngineId"]
    ctx.on_cleanup(lambda: _ac_delete_policy_engine(bac, engine_id))
    _poll(
        lambda: bac.get_policy_engine(policyEngineId=engine_id),
        lambda r: r["status"] != "CREATING",
        timeout_s=120.0,
    )

    policy_name = _alnum(ctx, "sim2realPol", 48)
    statement = f'permit(principal, action, resource == AgentCore::Gateway::"{gateway_arn}");'
    policy = bac.create_policy(
        name=policy_name,
        policyEngineId=engine_id,
        definition={"cedar": {"statement": statement}},
        validationMode="IGNORE_ALL_FINDINGS",
    )
    policy_id = policy["policyId"]
    _poll(
        lambda: bac.get_policy(policyEngineId=engine_id, policyId=policy_id),
        lambda r: r["status"] != "CREATING",
        timeout_s=120.0,
    )

    code, message = _error_detail(lambda: bac.delete_policy_engine(policyEngineId=engine_id))
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected_message = "Policy engine still contains 1 policy and cannot be deleted"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    still = bac.get_policy_engine(policyEngineId=engine_id)
    assert still["status"] != "DELETING", "policy engine entered DELETING despite the blocked call"
    still_policy = bac.get_policy(policyEngineId=engine_id, policyId=policy_id)
    assert still_policy["policyId"] == policy_id, "policy vanished despite the blocked engine delete"

    # Restore: remove the blocking policy, then the identical delete call must now succeed.
    bac.delete_policy(policyEngineId=engine_id, policyId=policy_id)
    _wait_gone(lambda: bac.get_policy(policyEngineId=engine_id, policyId=policy_id))

    del_resp = bac.delete_policy_engine(policyEngineId=engine_id)
    assert del_resp["status"] == "DELETING", (
        "expected the identical delete call to be accepted once the blocking policy is gone"
    )
    gone_message = _wait_gone(lambda: bac.get_policy_engine(policyEngineId=engine_id), timeout_s=300.0)
    expected_gone = f"Policy engine with ID {engine_id} not found"
    assert gone_message == expected_gone, f"expected message {expected_gone!r}, got {gone_message!r}"


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


def _alnum(ctx, prefix: str, maxlen: int) -> str:
    raw = ctx.unique_name(prefix)
    name = re.sub(r"[^A-Za-z0-9_]", "", raw)
    return name[:maxlen]


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


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _poll(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _wait_gone(probe, timeout_s=120.0, interval_s=3.0) -> str:
    """Poll probe() until it raises ResourceNotFoundException; return its message. Raise on timeout."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            probe()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return exc.response["Error"].get("Message", "")
            raise
        time.sleep(interval_s)
    raise AssertionError(f"resource did not disappear within {timeout_s}s")


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


def _create_gateway_with_retry(bac, **kwargs):
    """Retry CreateGateway while the just-created role has not yet propagated
    through IAM (AccessDeniedException), bounded rather than an unconditional sleep."""
    deadline = time.monotonic() + 30.0
    while True:
        try:
            return bac.create_gateway(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() >= deadline:
                raise
            time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
