"""gateway-create-lifecycle-ready."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gateway-create-lifecycle-ready"
GROUP = "state"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGateway starts CREATING and converges to READY with a gatewayUrl."""
    control = ctx.client("bedrock-agentcore-control")
    role_arn = _create_gateway_role(ctx)

    name = ctx.unique_name("sim2real-gw-lifecycle-")
    create_resp = control.create_gateway(
        name=name,
        roleArn=role_arn,
        authorizerType="AWS_IAM",
        protocolType="MCP",
        tags={"sim2real": CHECK},
    )
    gateway_id = create_resp["gatewayId"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(control, gateway_id))

    assert create_resp["status"] in ("CREATING", "READY"), (
        f"expected CreateGateway status in (CREATING, READY), got {create_resp['status']!r}"
    )

    final = _poll_until(
        lambda: control.get_gateway(gatewayIdentifier=gateway_id),
        lambda g: g["status"] in ("READY", "FAILED"),
        timeout_s=180,
        interval_s=5,
    )
    assert final["status"] == "READY", (
        f"gateway ended in {final['status']!r}: {final.get('statusReasons')}"
    )
    assert final["name"] == name, f"expected name {name!r}, got {final['name']!r}"
    assert final["gatewayUrl"], f"expected a non-empty gatewayUrl, got {final.get('gatewayUrl')!r}"
    assert final["gatewayArn"].endswith(gateway_id), (
        f"expected gatewayArn to end with {gateway_id!r}, got {final['gatewayArn']!r}"
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
