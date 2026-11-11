"""resource-policy-put-get-delete-roundtrip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-put-get-delete-roundtrip"
GROUP = "state"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy on a gateway echoes the exact policy document and GetResourcePolicy returns it; after
    DeleteResourcePolicy a second delete answers ResourceNotFoundException "Resource Policy doesn't exist for
    requested arn"."""
    control = ctx.client("bedrock-agentcore-control")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_arn = _create_gateway_role(ctx)

    gw = control.create_gateway(
        name=ctx.unique_name("sim2real-gw-respolicy-"),
        roleArn=role_arn,
        authorizerType="AWS_IAM",
        tags={"sim2real": CHECK},
    )
    gateway_id = gw["gatewayId"]
    gateway_arn = gw["gatewayArn"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(control, gateway_id))

    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Sim2RealAllowCrossAccountInvoke",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "bedrock-agentcore:InvokeGateway",
                    "Resource": gateway_arn,
                }
            ],
        }
    )

    put_resp = control.put_resource_policy(resourceArn=gateway_arn, policy=policy_doc)
    put_policy = json.loads(put_resp["policy"])
    assert put_policy == json.loads(policy_doc), f"put echo mismatch: {put_policy!r}"

    get_resp = control.get_resource_policy(resourceArn=gateway_arn)
    get_policy = json.loads(get_resp["policy"])
    assert get_policy == json.loads(policy_doc), f"get after put mismatch: {get_policy!r}"

    control.delete_resource_policy(resourceArn=gateway_arn)
    # A second delete on the now policy-less resource is the authoritative "gone"
    # signal: GetResourcePolicy's read path is cached independently of the delete and
    # can keep echoing the deleted policy past this window, whereas DeleteResourcePolicy
    # itself must reject the same way it would for a resource that never had a policy.
    code, message = _error(
        lambda: control.delete_resource_policy(resourceArn=gateway_arn),
        until_code="ResourceNotFoundException",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert code == "ResourceNotFoundException", (
        f"expected second delete to report ResourceNotFoundException, got {code!r}"
    )
    expected = "Resource Policy doesn't exist for requested arn"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _error(fn, *, until_code=None, timeout_s=0.0, interval_s=3.0):
    """Return (code, message) of the ClientError fn() raises. With until_code, retry while fn()
    succeeds or raises another code, for up to timeout_s. A call that never fails raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as err:
            error = err.response["Error"]
            if until_code is None or error["Code"] == until_code or time.monotonic() >= deadline:
                return error["Code"], error.get("Message", "")
        else:
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"expected a ClientError, but the call succeeded and returned {result!r}"
                )
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
