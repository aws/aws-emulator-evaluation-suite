"""delete-gateway-with-active-targets-conflict."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-gateway-with-active-targets-conflict"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteGateway while a target exists is refused with ValidationException and the exact has-targets message,
    leaving gateway and target readable; after the target is gone the delete succeeds and GetGateway answers
    ResourceNotFoundException with the exact message."""
    client = ctx.client("bedrock-agentcore-control")
    role_arn = _create_agentcore_execution_role(ctx, "gwconf")

    gateway_name = ctx.unique_name("sim2real-gw-target-")[:48]
    gateway = _retry_until_role_usable(
        lambda: client.create_gateway(
            name=gateway_name,
            roleArn=role_arn,
            authorizerType="AWS_IAM",
            tags={"env": "sim2real-test", "purpose": CHECK},
        )
    )
    gateway_id = gateway["gatewayId"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(client, gateway_id))
    _poll_until(
        lambda: client.get_gateway(gatewayIdentifier=gateway_id),
        lambda r: r["status"] != "CREATING",
        timeout_s=120.0,
    )

    target_name = ctx.unique_name("sim2real-gwt-tgt-")[:100]
    target = client.create_gateway_target(
        gatewayIdentifier=gateway_id,
        name=target_name,
        targetConfiguration={
            "mcp": {"mcpServer": {"endpoint": "https://example.com/mcp"}}
        },
    )
    target_id = target["targetId"]
    _poll_until(
        lambda: client.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id),
        lambda r: r["status"] not in ("CREATING", "SYNCHRONIZING"),
        timeout_s=120.0,
    )

    code, message = _error_detail(lambda: client.delete_gateway(gatewayIdentifier=gateway_id))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        f"Gateway with ID: {gateway_id} has targets associated with it. "
        "Delete all targets before deleting the gateway."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: neither the gateway nor its target were removed by the rejected call.
    got_gateway = client.get_gateway(gatewayIdentifier=gateway_id)
    assert got_gateway["gatewayId"] == gateway_id, (
        f"gateway {gateway_id!r} should still exist after the rejected delete, "
        f"got {got_gateway!r}"
    )
    got_target = client.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id)
    assert got_target["targetId"] == target_id, (
        f"target {target_id!r} should still exist after the rejected delete, "
        f"got {got_target!r}"
    )

    # Positive control: remove the target, wait for it to actually disappear, then the
    # gateway becomes deletable.
    client.delete_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id)

    target_code, target_message = _poll_gone(
        lambda: client.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id),
        timeout_s=120.0,
    )
    assert target_code == "ResourceNotFoundException", f"expected not-found, got {target_code!r}"
    expected_target_message = "Failed to retrieve target because it doesn't exist. Retry the request with a different resource identifier."
    assert target_message == expected_target_message, f"expected message {expected_target_message!r}, got {target_message!r}"

    client.delete_gateway(gatewayIdentifier=gateway_id)

    # Deletes prove gone: an independent read at the destination now returns the
    # specific not-found code, not just "the mutating call didn't raise".
    final_code, final_message = _poll_gone(
        lambda: client.get_gateway(gatewayIdentifier=gateway_id), timeout_s=90.0
    )
    assert final_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for deleted gateway {gateway_id!r}, "
        f"got {final_code!r}"
    )
    expected_final_message = "Failed to retrieve gateway because it doesn't exist. Retry the request with a different resource identifier."
    assert final_message == expected_final_message, (
        f"expected message {expected_final_message!r}, got {final_message!r}"
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


def _error_detail(fn):
    """Return (code, message) of the ClientError fn raises; a success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_gone(read, timeout_s=120.0, interval_s=3.0):
    """Poll read() until it raises ClientError; return (code, message). Raise on timeout."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = read()
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
        time.sleep(interval_s)
    raise AssertionError(f"resource still readable after {timeout_s}s; last value={last!r}")


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _create_agentcore_execution_role(ctx, name_hint):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-bac-{name_hint}-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Arn"]


def _retry_until_role_usable(fn, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

