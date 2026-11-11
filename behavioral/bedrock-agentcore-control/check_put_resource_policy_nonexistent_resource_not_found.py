"""put-resource-policy-nonexistent-resource-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-resource-policy-nonexistent-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy against a resource ARN that does not exist returns
    ResourceNotFoundException, while the same call against a real resource succeeds
    (positive control) and the policy is retrievable afterwards."""
    client = ctx.client("bedrock-agentcore-control")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    fake_arn = f"arn:aws:bedrock-agentcore:{ctx.region}:{account_id}:gateway/sim2real-missing-gw-0000000000"
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "bedrock-agentcore:InvokeGateway",
                    "Resource": fake_arn,
                }
            ],
        }
    )

    code, message = _error(lambda: client.put_resource_policy(resourceArn=fake_arn, policy=policy_doc))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = "ResourceArn provided in the request does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no policy exists for the nonexistent ARN.
    code2, message2 = _error(lambda: client.get_resource_policy(resourceArn=fake_arn))
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}"
    expected = "ResourceArn provided in the request does not exist"
    assert message2 == expected, f"expected message {expected!r}, got {message2!r}"

    # Positive control: create a real gateway, then PutResourcePolicy on its ARN succeeds.
    gateway_name = ctx.unique_name("sim2real-prp-gw-")
    role_arn = f"arn:aws:iam::{account_id}:role/sim2real-fake-gateway-role"
    created = client.create_gateway(name=gateway_name, roleArn=role_arn, authorizerType="NONE")
    gateway_id = created["gatewayId"]
    gateway_arn = created["gatewayArn"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(client, gateway_id))

    real_policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "bedrock-agentcore:InvokeGateway",
                    "Resource": gateway_arn,
                }
            ],
        }
    )
    client.put_resource_policy(resourceArn=gateway_arn, policy=real_policy_doc)
    ctx.on_cleanup(lambda: _best_effort_delete_policy(client, gateway_arn))
    got = client.get_resource_policy(resourceArn=gateway_arn)
    got_policy, expected_policy = json.loads(got["policy"]), json.loads(real_policy_doc)
    assert got_policy == expected_policy, f"expected {expected_policy}, got {got_policy}"


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
    """Return (code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _best_effort_delete_policy(client, resource_arn: str) -> None:
    try:
        client.delete_resource_policy(resourceArn=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
