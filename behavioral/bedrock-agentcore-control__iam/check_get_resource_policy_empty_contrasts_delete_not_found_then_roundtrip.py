"""get-resource-policy-empty-contrasts-delete-not-found-then-roundtrip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-resource-policy-empty-contrasts-delete-not-found-then-roundtrip"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore-control", "iam"]

_NOT_FOUND = ("ResourceNotFoundException", "Resource Policy doesn't exist for requested arn")

_AC_TRANSITIONAL = ("CREATING", "UPDATING", "DELETING", "SYNCHRONIZING")


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        got = (err.get("Code"), err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


def expect_error_eventually(fn, code, message, *, timeout_s=60.0, interval_s=3.0):
    """Like ``expect_error``, but a success races an in-flight prior write: retry until
    ``fn()`` raises ``(code, message)`` or the deadline passes."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response["Error"]
            got = (err.get("Code"), err.get("Message"))
            if got == (code, message) or time.monotonic() >= deadline:
                assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
                return
        else:
            assert time.monotonic() < deadline, (
                f"expected {code} but the call kept succeeding: {result!r}"
            )
        time.sleep(interval_s)


def _poll_until_policy(get_policy, expected: dict, *, timeout_s=90.0, interval_s=3.0):
    """Poll ``get_policy()`` until it returns ``expected``; raise with the last value seen."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = get_policy()
        if last == expected:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"policy never converged to {expected!r}; last seen {last!r}")


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


def _delete_gateway(control, gateway_id):
    _ac_delete_and_wait(
        lambda: control.get_gateway(gatewayIdentifier=gateway_id)["status"],
        lambda: control.delete_gateway(gatewayIdentifier=gateway_id),
        what=f"gateway {gateway_id}",
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """On a READY gateway that never had a policy, GetResourcePolicy returns 200 with the
    field absent while DeleteResourcePolicy is refused ResourceNotFoundException; Put then
    echoes the document exactly, Get returns it, and only a second delete repeats the refusal."""
    control = ctx.client("bedrock-agentcore-control")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    role_arn = role["Role"]["Arn"]

    gateway_name = ctx.unique_name("sim2real-gmrp-gw-")
    created = control.create_gateway(name=gateway_name, roleArn=role_arn, authorizerType="AWS_IAM")
    gateway_id = created["gatewayId"]
    gateway_arn = created["gatewayArn"]
    ctx.on_cleanup(lambda: _delete_gateway(control, gateway_id))

    deadline = time.monotonic() + 300.0
    status = created["status"]
    while status != "READY":
        assert status not in ("FAILED", "CREATE_FAILED"), f"gateway reached {status!r} while provisioning"
        assert time.monotonic() < deadline, f"gateway still {status!r} after 300s"
        time.sleep(5)
        status = control.get_gateway(gatewayIdentifier=gateway_id)["status"]

    # Never policied: GetResourcePolicy succeeds with the field absent, not ResourceNotFoundException.
    empty = control.get_resource_policy(resourceArn=gateway_arn)
    assert "policy" not in empty, f"expected no 'policy' field on an unpolicied gateway, got {empty!r}"

    # On the identical never-policied resource, DeleteResourcePolicy is refused.
    expect_error(lambda: control.delete_resource_policy(resourceArn=gateway_arn), *_NOT_FOUND)

    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowCrossAccountInvoke",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
                    "Action": "bedrock-agentcore:InvokeGateway",
                    "Resource": gateway_arn,
                }
            ],
        }
    )
    put_resp = control.put_resource_policy(resourceArn=gateway_arn, policy=policy_doc)
    put_policy = json.loads(put_resp["policy"])
    expected_policy = json.loads(policy_doc)
    assert put_policy == expected_policy, f"put echo mismatch: {put_policy!r}"

    # PutResourcePolicy can be eventually consistent, so the confirming read is a poll to the
    # exact expected document rather than a single read.
    _poll_until_policy(
        lambda: json.loads(control.get_resource_policy(resourceArn=gateway_arn)["policy"]),
        expected_policy,
    )

    control.delete_resource_policy(resourceArn=gateway_arn)

    # A second delete can still race the first one's propagation and briefly succeed again;
    # retry until it reports the resource is gone, the way the first, never-policied delete did.
    expect_error_eventually(lambda: control.delete_resource_policy(resourceArn=gateway_arn), *_NOT_FOUND)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
