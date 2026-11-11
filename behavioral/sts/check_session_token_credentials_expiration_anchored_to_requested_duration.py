"""session-token-credentials-expiration-anchored-to-requested-duration."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "session-token-credentials-expiration-anchored-to-requested-duration"
GROUP = "visibility-timeout-ttl"
SERVICES = ["sts"]


@tags("axis:happy-path", "cap:c7", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """GetSessionToken credentials authenticate immediately, their Expiration is issue time plus
    the requested DurationSeconds, and a duration below the 900s minimum is a ValidationError."""
    user_creds, _ = _iam_user_creds(ctx)
    sts = ctx.client("sts", creds=user_creds)
    unvalidated_sts = ctx.client("sts", creds=user_creds, config=Config(parameter_validation=False))
    base_identity = sts.get_caller_identity()

    before = datetime.now(timezone.utc)
    resp = sts.get_session_token(DurationSeconds=900)
    after = datetime.now(timezone.utc)
    creds = resp["Credentials"]
    session_client = ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    # Positive control: freshly-issued credentials authenticate immediately and
    # resolve to the SAME identity as the long-term caller (GetSessionToken does
    # not change identity, only issues temporary keys for it).
    identity = session_client.get_caller_identity()
    assert identity["Account"] == base_identity["Account"]
    assert identity["Arn"] == base_identity["Arn"]

    # The TTL contract: Expiration must land within [before, after] + 900s, i.e. the
    # server anchors the window to its OWN issue time plus exactly the requested
    # duration -- not some other value.
    expiration = creds["Expiration"]
    assert before.timestamp() + 900 - 5 <= expiration.timestamp() <= after.timestamp() + 900 + 5, (
        f"Expiration {expiration} is not requested-duration-900s from issuance "
        f"window [{before}, {after}]"
    )

    # A duration below the 900s floor must be rejected by the service, not clamped. Client-side
    # parameter validation is disabled so the request reaches the service instead of botocore.
    error = _error(lambda: unvalidated_sts.get_session_token(DurationSeconds=500))
    assert error.get("Code") == "ValidationError", f"unexpected code: {error.get('Code')!r}"
    expected_message = (
        "1 validation error detected: Value '500' at 'durationSeconds' failed to satisfy "
        "constraint: Member must have value greater than or equal to 900"
    )
    assert error.get("Message") == expected_message, (
        f"unexpected message: expected {expected_message!r}, got {error.get('Message')!r}"
    )


def _error(fn) -> dict:
    """Call fn() and return the botocore Error (Code and Message) it raises; an unexpected
    success raises rather than surfacing as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _iam_user_creds(ctx, policy=None):
    """A fresh IAM user's long-term access key (``creds`` for ctx.client) and the user's ARN.

    GetSessionToken and GetFederationToken take an IAM user's long-term credentials, so the
    check signs them with a user of its own instead of the runner's identity.
    """
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-stsuser-")
    user = iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])["User"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    if policy is not None:
        iam.put_user_policy(
            UserName=user_name, PolicyName="sim2real-behav-sts", PolicyDocument=json.dumps(policy)
        )
        ctx.on_cleanup(
            lambda: iam.delete_user_policy(UserName=user_name, PolicyName="sim2real-behav-sts")
        )
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    key_id = key["AccessKeyId"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key_id))
    creds = {"aws_access_key_id": key_id, "aws_secret_access_key": key["SecretAccessKey"]}
    # A new access key is eventually consistent: poll until STS accepts it.
    probe = ctx.client("sts", creds=creds)
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else min(60.0, max(left - 30.0, 0.0)))
    while True:
        try:
            probe.get_caller_identity()
            return creds, user["Arn"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"the new IAM user's access key never authenticated: {code!r}"
                ) from exc
        time.sleep(2.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

