"""gateway-duplicate-name-conflict-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gateway-duplicate-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateGateway with a name in use is refused with ConflictException "A gateway with name '<name>'
    already exists in this account", leaving the original intact; after the original is deleted the same create
    succeeds."""
    control = ctx.client("bedrock-agentcore-control")
    role_arn = _create_gateway_role(ctx)

    name = ctx.unique_name("sim2real-gw-dup-")
    first = _retry_until_role_usable(
        lambda: control.create_gateway(name=name, roleArn=role_arn, authorizerType="AWS_IAM")
    )
    first_id = first["gatewayId"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(control, first_id))

    code, message = _error(
        lambda: control.create_gateway(name=name, roleArn=role_arn, authorizerType="AWS_IAM")
    )
    assert code == "ConflictException", f"expected ConflictException for duplicate name, got {code!r}"
    expected = f"A gateway with name '{name}' already exists in this account"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the original gateway is unaffected by the rejected duplicate.
    still_there = control.get_gateway(gatewayIdentifier=first_id)
    assert still_there["name"] == name, (
        f"expected original gateway name {name!r} unchanged, got {still_there['name']!r}"
    )
    assert still_there["status"] != "DELETING", (
        f"rejected duplicate create left the original gateway {first_id} in status "
        f"{still_there['status']!r}"
    )

    # restore: freeing the name by deleting the original makes the identical call succeed,
    # proving the earlier rejection tracked this specific name conflict and not some other fault.
    # DeleteGateway rejects a gateway still in CREATING, so wait for a terminal state first.
    _poll_until(
        lambda: control.get_gateway(gatewayIdentifier=first_id),
        lambda r: r["status"] != "CREATING",
        timeout_s=120.0,
    )
    control.delete_gateway(gatewayIdentifier=first_id)
    _wait_rejected(lambda: control.get_gateway(gatewayIdentifier=first_id), timeout_s=90.0)

    second = _retry_until_role_usable(
        lambda: control.create_gateway(name=name, roleArn=role_arn, authorizerType="AWS_IAM")
    )
    second_id = second["gatewayId"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(control, second_id))

    # terminal read: independent of the mutating create call, at the destination.
    second_state = control.get_gateway(gatewayIdentifier=second_id)
    assert second_state["name"] == name, (
        f"expected recreated gateway named {name!r}, got {second_state['name']!r}"
    )
    assert second_state["status"] in ("CREATING", "READY"), (
        f"expected recreated gateway CREATING or READY, got {second_state['status']!r}"
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


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _retry_until_role_usable(fn, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
