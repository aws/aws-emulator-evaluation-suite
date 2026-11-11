"""synchronize-gateway-targets-advances-last-synchronized-at."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# SynchronizeGatewayTargets refuses static target types (PASSTHROUGH, OPEN_API_SCHEMA) with a
# ValidationException, while an mcp.mcpServer target dials its endpoint, so a non-MCP endpoint fails
# that target with a network-shaped reason. An advancing lastSynchronizedAt is not asserted.

CHECK = "synchronize-gateway-targets-advances-last-synchronized-at"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore-control"]

_OPENAPI_SCHEMA = json.dumps(
    {
        "openapi": "3.0.3",
        "info": {"title": "sim2real-syncgt", "version": "1.0.0"},
        "servers": [{"url": "https://example.com/sim2real"}],
        "paths": {
            "/ping": {
                "get": {
                    "operationId": "ping",
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
)


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """SynchronizeGatewayTargets refuses PASSTHROUGH and OPEN_API_SCHEMA targets and an unknown target id with
    their exact messages, leaving lastSynchronizedAt unset; an mcp.mcpServer target on a non-MCP endpoint is
    FAILED with a network-shaped reason from a real dial."""
    bac = ctx.client("bedrock-agentcore-control")
    role_arn = _create_gateway_role(ctx)
    gateway_id = _create_ready_gateway(ctx, bac, role_arn)

    passthrough_id = _create_ready_target(
        ctx,
        bac,
        gateway_id,
        "sim2real-syncgt-pt-",
        {"http": {"passthrough": {"endpoint": "https://example.com/sim2real", "protocolType": "CUSTOM"}}},
    )
    assert _get_target(bac, gateway_id, passthrough_id).get("lastSynchronizedAt") is None, (
        f"a freshly created, never-synchronized passthrough target {passthrough_id} already "
        "reports a lastSynchronizedAt"
    )
    code, message = _refused_code_and_message(
        lambda: bac.synchronize_gateway_targets(
            gatewayIdentifier=gateway_id, targetIdList=[passthrough_id]
        ),
        subject="SynchronizeGatewayTargets(passthrough target)",
    )
    assert code == "ValidationException", (
        f"expected a PASSTHROUGH target's synchronize to be refused with ValidationException, "
        f"got {code!r}: {message!r}"
    )
    expected = "Target type PASSTHROUGH is not supported for synchronization"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    after_pt = _get_target(bac, gateway_id, passthrough_id)
    assert after_pt.get("lastSynchronizedAt") is None, (
        f"a refused synchronize gave passthrough target {passthrough_id} a lastSynchronizedAt "
        f"of {after_pt.get('lastSynchronizedAt')!r}"
    )

    openapi_id = _create_ready_target(
        ctx,
        bac,
        gateway_id,
        "sim2real-syncgt-oas-",
        {"mcp": {"openApiSchema": {"inlinePayload": _OPENAPI_SCHEMA}}},
    )
    code2, message2 = _refused_code_and_message(
        lambda: bac.synchronize_gateway_targets(
            gatewayIdentifier=gateway_id, targetIdList=[openapi_id]
        ),
        subject="SynchronizeGatewayTargets(openApiSchema target)",
    )
    assert code2 == "ValidationException", (
        f"expected an OPEN_API_SCHEMA target's synchronize to be refused with "
        f"ValidationException, got {code2!r}: {message2!r}"
    )
    expected = "Target type OPEN_API_SCHEMA is not supported for synchronization"
    assert message2 == expected, f"expected message {expected!r}, got {message2!r}"

    # Negative: a targetId absent from this gateway. Derived from a real one so it is
    # well-formed but definitely unknown.
    bogus_id = _sibling_id(passthrough_id)
    assert bogus_id != passthrough_id, (
        f"failed to derive a distinct absent target id from {passthrough_id!r}"
    )
    absent_code, absent_message = _refused_code_and_message(
        lambda: bac.get_gateway_target(gatewayIdentifier=gateway_id, targetId=bogus_id),
        subject=f"GetGatewayTarget({bogus_id})",
    )
    assert absent_code == "ResourceNotFoundException", (
        f"premise broken: {bogus_id!r} did not read as absent (ResourceNotFoundException), "
        f"got code={absent_code!r}"
    )
    expected = "Failed to retrieve target because it doesn't exist. Retry the request with a different resource identifier."
    assert absent_message == expected, f"expected message {expected!r}, got {absent_message!r}"
    refused, refused_message = _refused_code_and_message(
        lambda: bac.synchronize_gateway_targets(
            gatewayIdentifier=gateway_id, targetIdList=[bogus_id]
        ),
        subject=f"SynchronizeGatewayTargets({bogus_id})",
    )
    assert refused == "ResourceNotFoundException", (
        f"expected SynchronizeGatewayTargets on an unknown target to be refused with "
        f"ResourceNotFoundException, got {refused!r}"
    )
    expected = "Failed to retrieve target because it doesn't exist. Retry the request with a different resource identifier."
    assert refused_message == expected, f"expected message {expected!r}, got {refused_message!r}"
    # Effect absent, read through a different operation than the refused mutation.
    after_bogus = _get_target(bac, gateway_id, passthrough_id)
    assert after_bogus.get("lastSynchronizedAt") is None, (
        f"a synchronize refused for an unknown target id gave the real target "
        f"{passthrough_id} a lastSynchronizedAt of {after_bogus.get('lastSynchronizedAt')!r}"
    )

    # mcp.mcpServer is the one target type with no static schema. Pointed at a non-MCP
    # endpoint, its first fetch attempt — fired by CreateGatewayTarget itself, before any
    # explicit synchronize — fails with a network-shaped reason that only a real dial
    # produces, which is the proof this mechanism is live rather than a synchronous validator.
    mcp_id, first_status, first_reasons = _create_mcp_server_target(ctx, bac, gateway_id)
    assert first_status == "FAILED", (
        f"expected the bogus mcp.mcpServer target's first live-fetch attempt to leave it "
        f"FAILED, got {first_status!r} statusReasons={first_reasons!r}"
    )
    # message varies: the reason quotes how the endpoint answers the live dial, and its
    # wording varies between runs.
    assert "initialize handshake" in first_reasons or "did not respond" in first_reasons, (
        f"expected a network-shaped failure reason from a real dial, got {first_reasons!r}"
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


_TERMINAL = (
    "READY",
    "FAILED",
    "UPDATE_UNSUCCESSFUL",
    "SYNCHRONIZE_UNSUCCESSFUL",
)

_ROLE_PROPAGATION_REASON = "not authorized to assume the execution role"


def _sibling_id(target_id):
    """A well-formed-but-absent target id derived from a real one by rotating its last
    character, so nothing is fabricated from an account id or a guessed format."""
    last = target_id[-1]
    replacement = "A" if last != "A" else "B"
    return target_id[:-1] + replacement


def _poll_until(probe, predicate, reason, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {reason}; last value={last!r}")


def _refused_code_and_message(fn, subject):
    """Return (code, message); RAISES on unexpected success rather than returning a falsy
    sentinel."""
    try:
        fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"{subject} unexpectedly SUCCEEDED; expected it to be refused")


def _get_target(bac, gateway_id, target_id):
    return bac.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id)


def _create_ready_target(ctx, bac, gateway_id, name_prefix, target_configuration):
    """Create a target with a static (non-live-fetch) configuration, register cleanup, and
    wait for it to settle READY. Neither http.passthrough nor mcp.openApiSchema performs any
    live dial at creation, so no role-propagation race applies here."""
    target_name = _target_name(ctx, name_prefix)
    created = bac.create_gateway_target(
        gatewayIdentifier=gateway_id,
        name=target_name,
        targetConfiguration=target_configuration,
        credentialProviderConfigurations=[
            {
                "credentialProviderType": "GATEWAY_IAM_ROLE",
                "credentialProvider": {"iamCredentialProvider": {"service": "execute-api"}},
            }
        ],
    )
    target_id = created["targetId"]
    settled = _poll_until(
        lambda: _get_target(bac, gateway_id, target_id),
        lambda t: t["status"] in _TERMINAL,
        "the new gateway target to reach a terminal create status",
        timeout_s=180.0,
    )
    assert settled["status"] == "READY", (
        f"target {target_id} did not become READY: status={settled['status']!r} "
        f"statusReasons={settled.get('statusReasons')!r}"
    )
    return target_id


def _create_mcp_server_target(ctx, bac, gateway_id, deadline_s=90.0, interval_s=10.0):
    """An mcp.mcpServer target pointed at a definitely-non-MCP HTTPS endpoint. Its first fetch
    attempt (fired at CreateGatewayTarget itself) is expected to end FAILED with a
    network-shaped reason. Retries target creation, not just the create call: the live fetch
    can race the same IAM role-trust propagation _retry_until_role_usable already waits out for
    CreateGateway, and that specific race surfaces as a terminal FAILED status with
    _ROLE_PROPAGATION_REASON rather than as a synchronous ClientError — only that reason is
    retried; any other FAILED reason is returned as the real result."""
    deadline = time.monotonic() + deadline_s
    while True:
        target_name = _target_name(ctx, "sim2real-syncgt-mcp-")
        created = bac.create_gateway_target(
            gatewayIdentifier=gateway_id,
            name=target_name,
            targetConfiguration={
                "mcp": {"mcpServer": {"endpoint": "https://example.com/sim2real-mcp"}}
            },
            credentialProviderConfigurations=[
                {
                    "credentialProviderType": "GATEWAY_IAM_ROLE",
                    "credentialProvider": {"iamCredentialProvider": {"service": "execute-api"}},
                }
            ],
        )
        target_id = created["targetId"]
        settled = _poll_until(
            lambda: _get_target(bac, gateway_id, target_id),
            lambda t: t["status"] in _TERMINAL,
            "the bogus mcp.mcpServer target to reach a terminal create status",
            timeout_s=180.0,
        )
        reasons = " ".join(settled.get("statusReasons") or [])
        if settled["status"] != "FAILED" or _ROLE_PROPAGATION_REASON not in reasons:
            return target_id, settled["status"], reasons
        if time.monotonic() >= deadline:
            return target_id, settled["status"], reasons
        _safe_delete(
            lambda: bac.delete_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id)
        )
        time.sleep(interval_s)


def _create_ready_gateway(ctx, bac, role_arn):
    gateway_name = _gateway_name(ctx, "sim2real-gw-syncgt-")
    gw = _retry_until_role_usable(
        lambda: bac.create_gateway(
            name=gateway_name,
            roleArn=role_arn,
            authorizerType="AWS_IAM",
            tags={"sim2real": CHECK},
        )
    )
    gateway_id = gw["gatewayId"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(bac, gateway_id))
    settled = _poll_until(
        lambda: bac.get_gateway(gatewayIdentifier=gateway_id),
        lambda g: g["status"] in ("READY", "FAILED"),
        "the gateway to reach a terminal create status",
        timeout_s=240.0,
    )
    assert settled["status"] == "READY", (
        f"gateway {gateway_id} did not become READY: status={settled['status']!r} "
        f"statusReasons={settled.get('statusReasons')!r}"
    )
    return gateway_id


def _gateway_name(ctx, prefix):
    raw = ctx.unique_name(prefix)
    return "".join(c for c in raw if c.isalnum() or c == "-")[:48].rstrip("-")


def _target_name(ctx, prefix):
    raw = ctx.unique_name(prefix)
    return "".join(c for c in raw if c.isalnum() or c in "-_")[:48]


def _create_gateway_role(ctx):
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-bac-syncgt-")[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete(lambda: iam.delete_role(RoleName=role_name)))
    policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(
        lambda: _safe_delete(
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        )
    )
    return f"arn:aws:iam::{account_id}:role/{role_name}"


def _retry_until_role_usable(fn, timeout_s=120.0, interval_s=6.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code in ("AccessDeniedException", "ValidationException") and (
                "role" in message.lower()
            ):
                last = err
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"role never became usable within {timeout_s}s; last error={last}")


def _safe_delete(fn):
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("ResourceNotFoundException", "NoSuchEntity"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
