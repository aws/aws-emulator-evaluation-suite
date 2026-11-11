"""delete-resource-policy-nonexistent-resource-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-resource-policy-nonexistent-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteResourcePolicy on an existing gateway with no policy answers ResourceNotFoundException "Resource Policy
    doesn't exist for requested arn" and leaves the gateway; after a policy is put and deleted, a second delete
    answers the same code and message."""
    client = ctx.client("bedrock-agentcore-control")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    gateway_name = ctx.unique_name("sim2real-drp-gw-")
    role_arn = f"arn:aws:iam::{account_id}:role/sim2real-fake-gateway-role"
    created = client.create_gateway(name=gateway_name, roleArn=role_arn, authorizerType="NONE")
    gateway_id = created["gatewayId"]
    gateway_arn = created["gatewayArn"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(client, gateway_id))

    # No policy has ever been attached to this real, existing gateway.
    code, message = _error_detail(lambda: client.delete_resource_policy(resourceArn=gateway_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = "Resource Policy doesn't exist for requested arn"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The gateway itself is unaffected by the failed delete-policy call.
    got = client.get_gateway(gatewayIdentifier=gateway_id)
    assert got["gatewayId"] == gateway_id, f"expected {gateway_id}, got {got['gatewayId']!r}"

    # Positive control: attach a policy, then delete it successfully.
    policy_doc = json.dumps(
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
    client.put_resource_policy(resourceArn=gateway_arn, policy=policy_doc)

    # PutResourcePolicy can be eventually consistent -- confirm the policy is actually
    # visible before deleting it, so Delete doesn't race an in-flight Put.
    _poll_until(
        lambda: _readable(lambda: client.get_resource_policy(resourceArn=gateway_arn)),
        lambda ok: ok,
        timeout_s=120.0,
        interval_s=5.0,
    )

    client.delete_resource_policy(resourceArn=gateway_arn)

    # GetResourcePolicy can keep returning a deleted policy for a minute, so it cannot serve as
    # the independent read here. A second delete on the now-policy-less resource must raise
    # ResourceNotFoundException, exactly like the pristine case above.
    deadline = time.monotonic() + 60.0
    while True:
        try:
            client.delete_resource_policy(resourceArn=gateway_arn)
        except ClientError as err:
            code2, message2 = err.response["Error"]["Code"], err.response["Error"].get("Message", "")
            if code2 == "ResourceNotFoundException" or time.monotonic() >= deadline:
                break
        else:
            # A second delete that succeeds has raced the first one's propagation.
            assert time.monotonic() < deadline, "a second DeleteResourcePolicy still succeeded after 60 s"
        time.sleep(2)
    assert code2 == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from a second delete, got {code2!r}"
    )
    expected_message2 = "Resource Policy doesn't exist for requested arn"
    assert message2 == expected_message2, f"expected message {expected_message2!r}, got {message2!r}"


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


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _error_detail(fn):
    """Return (code, message) of the ClientError fn raises; a success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _readable(read) -> bool:
    """True when read() returns; False when it raises ResourceNotFoundException."""
    try:
        read()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return False
    return True


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
