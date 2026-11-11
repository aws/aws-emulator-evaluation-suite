"""gateway-target-lifecycle-ready."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gateway-target-lifecycle-ready"
GROUP = "state"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGatewayTarget converges to READY and echoes back the configured
    passthrough endpoint; DeleteGatewayTarget makes it disappear."""
    control = ctx.client("bedrock-agentcore-control")
    role_arn = _create_gateway_role(ctx)

    gw = control.create_gateway(
        name=ctx.unique_name("sim2real-gw-target-"), roleArn=role_arn, authorizerType="AWS_IAM"
    )
    gateway_id = gw["gatewayId"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(control, gateway_id))
    _poll_until(
        lambda: control.get_gateway(gatewayIdentifier=gateway_id),
        lambda g: g["status"] in ("READY", "FAILED"),
        timeout_s=180,
        interval_s=5,
    )

    target_name = ctx.unique_name("sim2real-target-")
    endpoint = "https://example.com/anything"
    create_resp = control.create_gateway_target(
        gatewayIdentifier=gateway_id,
        name=target_name,
        targetConfiguration={
            "http": {"passthrough": {"endpoint": endpoint, "protocolType": "CUSTOM"}}
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
    target_id = create_resp["targetId"]

    final = _poll_until(
        lambda: control.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id),
        lambda t: t["status"] in ("READY", "FAILED"),
        timeout_s=120,
        interval_s=4,
    )
    assert final["status"] == "READY", f"target ended in {final['status']!r}: {final.get('statusReasons')}"
    assert final["name"] == target_name, f"expected name {target_name!r}, got {final['name']!r}"
    assert final["targetConfiguration"]["http"]["passthrough"]["endpoint"] == endpoint, (
        f"expected echoed endpoint {endpoint!r}, "
        f"got {final['targetConfiguration']['http']['passthrough']['endpoint']!r}"
    )

    control.delete_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id)
    code, message = _wait_rejected(
        lambda: control.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id),
        timeout_s=90.0,
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException on get after delete, got {code!r}"
    expected = (
        "Failed to retrieve target because it doesn't exist. "
        "Retry the request with a different resource identifier."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    # The deleted target must also be unusable, not merely absent from a read.
    mutate_code, mutate_message = _error(
        lambda: control.update_gateway_target(
            gatewayIdentifier=gateway_id,
            targetId=target_id,
            name=target_name,
            targetConfiguration={
                "http": {"passthrough": {"endpoint": endpoint, "protocolType": "CUSTOM"}}
            },
        )
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"expected UpdateGatewayTarget on a deleted target to fail with ResourceNotFoundException, "
        f"got {mutate_code!r}"
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
