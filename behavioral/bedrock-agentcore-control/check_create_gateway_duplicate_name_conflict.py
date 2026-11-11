"""create-gateway-duplicate-name-conflict."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-gateway-duplicate-name-conflict"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateGateway with a name already in use in the account/region returns
    ConflictException rather than reusing or duplicating the existing gateway, and a
    CreateGateway with a fresh unique name still succeeds (positive control)."""
    client = ctx.client("bedrock-agentcore-control")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{account_id}:role/sim2real-fake-gateway-role"

    resource_tags = {"sim2real-check": CHECK}

    name = ctx.unique_name("sim2real-gw-dup-")
    first = client.create_gateway(
        name=name, roleArn=role_arn, protocolType="MCP", authorizerType="NONE", tags=resource_tags
    )
    first_id = first["gatewayId"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(client, first_id))

    code, message = _error_detail(
        lambda: client.create_gateway(
            name=name,
            roleArn=role_arn,
            protocolType="MCP",
            authorizerType="NONE",
            tags=resource_tags,
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    expected_message = f"A gateway with name '{name}' already exists in this account"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: only the first gateway exists under that name/id; listing gateways
    # by name shows exactly one match.
    matches = [g for g in _list_all_gateways(client) if g["name"] == name]
    assert len(matches) == 1, f"expected exactly 1 gateway named {name}, found {len(matches)}"
    assert matches[0]["gatewayId"] == first_id

    # Positive control: a different, fresh name succeeds. Terminal read is independent
    # of the mutating CreateGateway call: GetGateway must show the new gateway under
    # its own id, at the destination, not just echo the create response.
    other_name = ctx.unique_name("sim2real-gw-dup-other-")
    second = client.create_gateway(
        name=other_name,
        roleArn=role_arn,
        protocolType="MCP",
        authorizerType="NONE",
        tags=resource_tags,
    )
    second_id = second["gatewayId"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(client, second_id))
    assert second["name"] == other_name

    fetched = client.get_gateway(gatewayIdentifier=second_id)
    assert fetched["name"] == other_name, (
        f"expected GetGateway to show name {other_name}, got {fetched.get('name')}"
    )
    assert fetched["gatewayId"] == second_id


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


def _error_detail(fn):
    """Return (code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected the duplicate CreateGateway to be rejected, but it SUCCEEDED and "
        f"returned {result!r}"
    )


def _list_all_gateways(client):
    items = []
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        page = client.list_gateways(**kwargs)
        items.extend(page.get("items", []))
        next_token = page.get("nextToken")
        if not next_token:
            break
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
