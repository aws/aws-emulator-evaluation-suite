"""get-session-token-duration-below-minimum-rejected."""
from __future__ import annotations

import json
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-session-token-duration-below-minimum-rejected"
GROUP = 'error-semantics'
SERVICES = ['sts']

@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DurationSeconds below the 900s minimum must be rejected on GetSessionToken."""

    def _unvalidated_client(service="sts"):
        # Disable botocore client-side parameter validation so the SERVICE's own input
        # validation error codes surface instead of a local ParamValidationError.
        return ctx.client(
            service,
            creds=user_creds,
            config=Config(retries={"max_attempts": 1}, parameter_validation=False),
        )

    def _refusal(fn):
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError(
            f"expected DurationSeconds < 900 to be rejected, but it SUCCEEDED and returned {result!r}"
        )

    user_creds, _ = _iam_user_creds(ctx)
    client = _unvalidated_client()

    # Positive control: the documented floor itself (900s) must be ACCEPTED, so this check
    # cannot pass merely because the target refuses every GetSessionToken call.
    accepted = client.get_session_token(DurationSeconds=900)
    creds = accepted["Credentials"]
    assert creds["SessionToken"] and creds["AccessKeyId"], (
        f"expected DurationSeconds=900 (the documented minimum) to succeed, got {accepted!r}"
    )

    code, message = _refusal(lambda: client.get_session_token(DurationSeconds=100))
    assert code == "ValidationError", (
        f"expected ValidationError for DurationSeconds < 900, got {code}"
    )
    expected_message = (
        "1 validation error detected: Value '100' at 'durationSeconds' failed to satisfy "
        "constraint: Member must have value greater than or equal to 900"
    )
    assert message == expected_message, (
        f"expected the refusal message {expected_message!r}, got {message!r}"
    )


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
