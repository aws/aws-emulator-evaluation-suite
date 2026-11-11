"""gateway-target-lifecycle-transitions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gateway-target-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A GatewayTarget bound to a Gateway reaches READY, keeps its own status
    independent of an unrelated parent UpdateGateway, follows its own
    create/update/delete state machine, and disappears on delete."""
    bac = ctx.client("bedrock-agentcore-control")
    role_arn = _create_agentcore_execution_role(ctx, "gwt")
    gw_name = ctx.unique_name("sim2real-gwt-")[:48]

    gw = _retry_until_role_usable(
        lambda: bac.create_gateway(
            name=gw_name,
            roleArn=role_arn,
            authorizerType="AWS_IAM",
            tags={"sim2real:managed": "true", "sim2real:check": CHECK},
        )
    )
    gateway_id = gw["gatewayId"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(bac, gateway_id))
    _poll_until(
        lambda: bac.get_gateway(gatewayIdentifier=gateway_id),
        lambda r: r["status"] != "CREATING",
        timeout_s=120.0,
    )

    target_name = ctx.unique_name("sim2real-tgt-")[:100]
    target_config_v1 = {
        "http": {"passthrough": {"endpoint": "https://example.com/mcp-v1", "protocolType": "MCP"}}
    }
    target = bac.create_gateway_target(
        gatewayIdentifier=gateway_id, name=target_name, targetConfiguration=target_config_v1
    )
    target_id = target["targetId"]
    state = _poll_until(
        lambda: bac.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id),
        lambda r: r["status"] not in ("CREATING", "SYNCHRONIZING"),
        timeout_s=120.0,
    )
    assert state["status"] == "READY", f"unexpected terminal status {state['status']!r}"

    # An unrelated parent gateway update must not disturb the target's state.
    bac.update_gateway(
        gatewayIdentifier=gateway_id,
        name=gw_name,
        roleArn=role_arn,
        authorizerType="AWS_IAM",
        description="sim2real-parent-touch",
    )
    _poll_until(
        lambda: bac.get_gateway(gatewayIdentifier=gateway_id),
        lambda r: r["status"] != "UPDATING",
        timeout_s=120.0,
    )
    still = bac.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id)
    assert still["status"] == "READY", f"unrelated parent update disturbed target: {still['status']!r}"

    target_config_v2 = {
        "http": {"passthrough": {"endpoint": "https://example.com/mcp-v2", "protocolType": "MCP"}}
    }
    bac.update_gateway_target(
        gatewayIdentifier=gateway_id,
        targetId=target_id,
        name=target_name,
        targetConfiguration=target_config_v2,
    )
    state2 = _poll_until(
        lambda: bac.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id),
        lambda r: r["status"] not in ("UPDATING", "SYNCHRONIZING"),
        timeout_s=120.0,
    )
    assert state2["status"] == "READY", f"unexpected terminal status {state2['status']!r}"
    got_endpoint = state2["targetConfiguration"]["http"]["passthrough"]["endpoint"]
    assert got_endpoint == "https://example.com/mcp-v2", (
        f"expected updated endpoint 'https://example.com/mcp-v2', got {got_endpoint!r}"
    )

    bac.delete_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id)
    code, message = _wait_rejected(
        lambda: bac.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id),
        timeout_s=90.0,
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = (
        "Failed to retrieve target because it doesn't exist. "
        "Retry the request with a different resource identifier."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The dead target id must also reject a mutation, not just a read.
    mutate_code, mutate_message = _error(
        lambda: bac.update_gateway_target(
            gatewayIdentifier=gateway_id,
            targetId=target_id,
            name=target_name,
            targetConfiguration=target_config_v2,
        )
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"mutation on deleted target should be rejected as not-found, got {mutate_code!r}"
    )
    assert mutate_message == expected, f"expected message {expected!r}, got {mutate_message!r}"


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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
