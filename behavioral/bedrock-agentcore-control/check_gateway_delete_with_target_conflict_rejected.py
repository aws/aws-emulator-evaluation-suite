"""gateway-delete-with-target-conflict-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gateway-delete-with-target-conflict-rejected"
GROUP = "state"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteGateway while a target exists is refused with ValidationException and the exact has-targets message,
    leaving gateway and target READY; once the target is gone the gateway deletes and stops reading."""
    control = ctx.client("bedrock-agentcore-control")
    role_arn = _create_gateway_role(ctx)

    name = ctx.unique_name("sim2real-gw-tgtconflict-")
    gw = control.create_gateway(
        name=name, roleArn=role_arn, authorizerType="AWS_IAM", tags={"sim2real": CHECK}
    )
    gateway_id = gw["gatewayId"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(control, gateway_id))
    _poll_until(
        lambda: control.get_gateway(gatewayIdentifier=gateway_id),
        lambda g: g["status"] in ("READY", "FAILED"),
        timeout_s=180,
        interval_s=5,
    )

    target = control.create_gateway_target(
        gatewayIdentifier=gateway_id,
        name=ctx.unique_name("sim2real-target-"),
        targetConfiguration={
            "http": {
                "passthrough": {
                    "endpoint": "https://example.com",
                    "protocolType": "CUSTOM",
                }
            }
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

    # let the gateway settle back into a stable state after the target
    # creation (which can transiently move it through UPDATING) before
    # attempting the delete.
    _poll_until(
        lambda: control.get_gateway(gatewayIdentifier=gateway_id),
        lambda g: g["status"] in ("READY", "FAILED"),
        timeout_s=120,
        interval_s=4,
    )
    _poll_until(
        lambda: control.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id),
        lambda t: t["status"] in ("READY", "FAILED"),
        timeout_s=120,
        interval_s=4,
    )

    # break: deleting the gateway while its target still exists is rejected,
    # not cascaded.
    code, message = _error(lambda: control.delete_gateway(gatewayIdentifier=gateway_id))
    assert code == "ValidationException", (
        f"expected DeleteGateway to be rejected while a target is attached, got {code!r}: {message!r}"
    )
    expected_message = (
        f"Gateway with ID: {gateway_id} has targets associated with it. Delete all targets "
        "before deleting the gateway."
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # effect absent: the rejected call left both the gateway and its target intact.
    gw_state = control.get_gateway(gatewayIdentifier=gateway_id)
    assert gw_state["status"] == "READY", f"expected gateway to remain READY, got {gw_state['status']!r}"
    tgt_state = control.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id)
    assert tgt_state["status"] == "READY", f"expected target to remain READY, got {tgt_state['status']!r}"

    # restore: remove the target, then the identical DeleteGateway call succeeds.
    control.delete_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id)
    _poll_until(
        lambda: _get_target_or_none(control, gateway_id, target_id),
        lambda t: t is None,
        timeout_s=90,
        interval_s=3,
    )

    control.delete_gateway(gatewayIdentifier=gateway_id)
    _poll_until(
        lambda: _get_gateway_or_none(control, gateway_id),
        lambda g: g is None,
        timeout_s=180,
        interval_s=5,
    )


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
            lambda t=target_id: control.get_gateway_target(gatewayIdentifier=gateway_id, targetId=t)["status"],
            lambda t=target_id: control.delete_gateway_target(gatewayIdentifier=gateway_id, targetId=t),
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _error(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected the call to raise a ClientError, but it succeeded")


def _get_gateway_or_none(control, gateway_id):
    try:
        return control.get_gateway(gatewayIdentifier=gateway_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _get_target_or_none(control, gateway_id, target_id):
    try:
        return control.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
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

