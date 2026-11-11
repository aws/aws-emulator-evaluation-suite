"""delete-gateway-without-iam-permission-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-gateway-without-iam-permission-denied"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteGateway by a role with no bedrock-agentcore permissions is refused with AccessDeniedException and the
    exact IAM message naming the role and gateway ARN, and the gateway does not enter DELETING; the same delete by
    the caller succeeds and GetGateway then answers ResourceNotFoundException."""
    client = ctx.client("bedrock-agentcore-control")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_arn_for_gateway = f"arn:aws:iam::{account_id}:role/sim2real-fake-gateway-role"

    name = ctx.unique_name("sim2real-gw-nodel-")
    gateway = client.create_gateway(name=name, roleArn=role_arn_for_gateway, authorizerType="NONE")
    gateway_id = gateway["gatewayId"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(client, gateway_id))

    restricted_role_arn = _create_deny_role(ctx, "dgw")
    creds = _assume_role_with_retry(ctx, restricted_role_arn)
    restricted = _client_with_creds(ctx, "bedrock-agentcore-control", creds)

    code, message = _error_detail(lambda: restricted.delete_gateway(gatewayIdentifier=gateway_id))
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    role_name = restricted_role_arn.rsplit("/", 1)[-1]
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/sim2real-behav is not authorized "
        f"to perform: bedrock-agentcore:DeleteGateway on resource: {gateway['gatewayArn']} because no "
        "identity-based policy allows the bedrock-agentcore:DeleteGateway action"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the gateway is untouched, not moved into DELETING.
    got = client.get_gateway(gatewayIdentifier=gateway_id)
    assert got["name"] == name
    assert got["status"] != "DELETING", f"gateway moved to DELETING despite denied caller: {got['status']}"

    # Positive control: the identical delete call with full permissions succeeds,
    # proven by an independent read at the destination, not by the delete call's
    # own response.
    deleted = client.delete_gateway(gatewayIdentifier=gateway_id)
    assert deleted["gatewayId"] == gateway_id
    code, message = _poll_gone(lambda: client.get_gateway(gatewayIdentifier=gateway_id), timeout_s=90.0)
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = "Failed to retrieve gateway because it doesn't exist. Retry the request with a different resource identifier."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


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
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = read()
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
        time.sleep(interval_s)
    raise AssertionError(f"resource still readable after {timeout_s}s; last value={last!r}")


def _iam_safe_name(ctx, suffix: str) -> str:
    raw = ctx.unique_name(f"sim2real-behav-{suffix}-")
    safe = "".join(c for c in raw if c.isalnum() or c in "+=,.@_-")
    return safe[:64]


def _create_deny_role(ctx, suffix: str) -> str:
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_name = _iam_safe_name(ctx, suffix)
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    ctx.on_cleanup(lambda: _best_effort_delete_role(iam, role_name))
    minimal_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sts:GetCallerIdentity", "Resource": "*"}],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="minimal-no-agentcore", PolicyDocument=json.dumps(minimal_policy)
    )
    return f"arn:aws:iam::{account_id}:role/{role_name}"


def _best_effort_delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="minimal-no-agentcore")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _assume_role_with_retry(ctx, role_arn: str, timeout_s: float = 60.0):
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-behav")["Credentials"]
        except ClientError as err:
            last_err = err
            time.sleep(3)
    raise AssertionError(f"could not assume restricted role in time: {last_err}")


def _client_with_creds(ctx, service: str, creds):
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
