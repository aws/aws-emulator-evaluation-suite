"""put-resource-policy-exceeds-max-length-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-resource-policy-exceeds-max-length-rejected"
GROUP = "overly-permissive"
SERVICES = ["secretsmanager"]

_MAX_RESOURCE_POLICY_LENGTH = 20480


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be refused, but it SUCCEEDED and returned {result!r}")


def _reap_secret(sm, secret_id, *, timeout_s: float = 60.0, interval_s: float = 2.0) -> None:
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.describe_secret(SecretId=secret_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"secret {secret_id} still present {timeout_s}s after ForceDeleteWithoutRecovery"
            )
        time.sleep(interval_s)


def _policy(ctx, *, sid: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": sid,
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
                    "Action": "secretsmanager:GetSecretValue",
                    "Resource": "*",
                }
            ],
        }
    )


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy refuses a resource policy longer than the 20480-character maximum,
    leaving the secret's previously attached policy in place.

    Reference: https://docs.aws.amazon.com/secretsmanager/latest/userguide/reference_limits.html
    """
    sm = ctx.client("secretsmanager")

    name = ctx.unique_name("sim2real-behav-respolicylen-")
    created = sm.create_secret(Name=name, SecretString="sim2real-respolicylen-value")
    arn = created["ARN"]
    ctx.on_cleanup(lambda: _reap_secret(sm, arn))

    # Positive control: an in-range policy is accepted and readable back.
    in_range = _policy(ctx, sid="SIM2REALINRANGE")
    assert len(in_range) <= _MAX_RESOURCE_POLICY_LENGTH, (
        f"the control policy must itself be in range; it is {len(in_range)} characters"
    )
    sm.put_resource_policy(SecretId=arn, ResourcePolicy=in_range)
    attached = sm.get_resource_policy(SecretId=arn).get("ResourcePolicy")
    assert json.loads(attached) == json.loads(in_range), (
        f"the in-range policy must be readable back with the same content (AWS reformats the "
        f"JSON text); got {attached!r}"
    )

    # Pad a statement's Sid with filler so the document's total length exceeds the maximum by
    # exactly one character, keeping it syntactically valid JSON.
    base_len = len(_policy(ctx, sid=""))
    filler_len = _MAX_RESOURCE_POLICY_LENGTH - base_len + 1
    oversized = _policy(ctx, sid="X" * filler_len)
    assert len(oversized) == _MAX_RESOURCE_POLICY_LENGTH + 1, (
        f"the oversized policy must be exactly one character over the maximum; it is "
        f"{len(oversized)} characters, maximum is {_MAX_RESOURCE_POLICY_LENGTH}"
    )

    code, message = _error_code(lambda: sm.put_resource_policy(SecretId=arn, ResourcePolicy=oversized))
    assert code == "InvalidParameterException", (
        f"a resource policy one character over the {_MAX_RESOURCE_POLICY_LENGTH}-character maximum "
        f"must be refused with InvalidParameterException; got {code!r}: {message!r}"
    )
    assert message == "ResourcePolicy exceeds size limit.", f"unexpected refusal message: {message!r}"

    # Effect absent: the refused oversized policy never replaced the in-range one.
    unchanged = sm.get_resource_policy(SecretId=arn).get("ResourcePolicy")
    assert json.loads(unchanged) == json.loads(in_range), (
        f"the refused oversized policy must not have replaced the attached one; got {unchanged!r}"
    )

    # The identical in-range call still succeeds, proving the ceiling, not PutResourcePolicy
    # itself, is what refused the oversized document.
    in_range_again = _policy(ctx, sid="SIM2REALAGAIN")
    sm.put_resource_policy(SecretId=arn, ResourcePolicy=in_range_again)
    final = sm.get_resource_policy(SecretId=arn).get("ResourcePolicy")
    assert json.loads(final) == json.loads(in_range_again), (
        f"a fresh in-range policy must still be accepted after the refusal; got {final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
