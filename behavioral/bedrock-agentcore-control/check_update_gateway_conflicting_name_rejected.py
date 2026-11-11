"""update-gateway-conflicting-name-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-gateway-conflicting-name-rejected"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second UpdateGateway issued right after a first is either accepted or refused with
    ValidationException and the exact Updating-state message; the settled READY gateway carries
    the description of the last accepted update, and a later update on READY is accepted."""
    client = ctx.client("bedrock-agentcore-control")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{account_id}:role/sim2real-fake-gateway-role"

    name = ctx.unique_name("sim2real-gw-upd-")
    gw = client.create_gateway(
        name=name, roleArn=role_arn, authorizerType="NONE", tags={"sim2real": CHECK}
    )
    gateway_id = gw["gatewayId"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(client, gateway_id))

    _poll_until(
        lambda: client.get_gateway(gatewayIdentifier=gateway_id),
        lambda r: r["status"] == "READY",
        timeout_s=120.0,
    )

    # Kick off the first update (moves the gateway to UPDATING) ...
    client.update_gateway(
        gatewayIdentifier=gateway_id,
        name=name,
        roleArn=role_arn,
        authorizerType="NONE",
        description="sim2real-first-update",
    )

    # ... and immediately issue a second update against the same gateway. AWS documents no
    # UPDATING duration, so the first update may already have settled: the second is either
    # refused with the Updating-state ValidationException or accepted.
    second_description = "sim2real-second-update-should-be-rejected"
    try:
        client.update_gateway(
            gatewayIdentifier=gateway_id,
            name=name,
            roleArn=role_arn,
            authorizerType="NONE",
            description=second_description,
        )
        accepted_description = second_description
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message", "")
        assert code == "ValidationException", f"expected ValidationException, got {code}: {message}"
        expected = (
            "UpdateGateway operation can't be performed on gateway when it is in Updating state. "
            "Retry the request when the gateway is in a valid state."
        )
        assert message == expected, f"expected message {expected!r}, got {message!r}"
        accepted_description = "sim2real-first-update"

    settled = _poll_until(
        lambda: client.get_gateway(gatewayIdentifier=gateway_id),
        lambda r: r["status"] != "UPDATING",
        timeout_s=120.0,
    )
    assert settled["status"] == "READY", f"unexpected terminal status {settled['status']!r}"
    # The settled description is the last accepted update; a refused update never takes effect.
    assert settled["description"] == accepted_description, (
        f"expected description {accepted_description!r}, got {settled['description']!r}"
    )

    # Positive control: now that the gateway is READY again, an update is accepted.
    client.update_gateway(
        gatewayIdentifier=gateway_id,
        name=name,
        roleArn=role_arn,
        authorizerType="NONE",
        description="sim2real-third-update-accepted",
    )
    settled2 = _poll_until(
        lambda: client.get_gateway(gatewayIdentifier=gateway_id),
        lambda r: r["status"] != "UPDATING",
        timeout_s=120.0,
    )
    assert settled2["status"] == "READY"
    assert settled2["description"] == "sim2real-third-update-accepted"


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


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

