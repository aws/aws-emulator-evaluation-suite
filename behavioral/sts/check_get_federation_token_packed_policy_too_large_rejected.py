"""get-federation-token-packed-policy-too-large-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-federation-token-packed-policy-too-large-rejected"
GROUP = 'error-semantics'
SERVICES = ['sts']

@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetFederationToken with 50 maximum-size session tags, each within its own limit, fails with
    PackedPolicyTooLarge and the documented message around the server-computed token size (4096-byte
    limit), after the same call with one small tag returns credentials."""

    user_creds, _ = _iam_user_creds(
        ctx,
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["sts:GetFederationToken", "sts:TagSession"], "Resource": "*"}],
        },
    )
    sts = ctx.client("sts", creds=user_creds)

    def _error_code(fn):
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001
            response = getattr(exc, "response", None)
            if response is not None:
                return response.get("Error", {}).get("Code"), response.get("Error", {}).get("Message")
            return type(exc).__name__, str(exc)
        raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")

    control = sts.get_federation_token(
        Name=ctx.unique_name("sim2real-behav-fed-")[:32],
        DurationSeconds=900,
        Tags=[{"Key": "Team", "Value": "engineering"}],
    )
    assert control["Credentials"]["AccessKeyId"], control

    # Tags rather than Policy (capped at 2048 chars, so ValidationError first) or AssumeRole
    # (authorization precedes packing). 50 tags, 128-char keys and 256-char values are each the
    # documented maximum, so only the packed-size budget is exceeded.
    huge_tags = [{"Key": f"k{i:02d}{'a' * 124}"[:128], "Value": ("v" * 256)} for i in range(50)]
    code, message = _error_code(
        lambda: sts.get_federation_token(
            Name=ctx.unique_name("sim2real-behav-fed-")[:32],
            DurationSeconds=900,
            Tags=huge_tags,
        )
    )
    assert code == "PackedPolicyTooLarge", f"expected PackedPolicyTooLarge, got {code}"
    # The token size is computed server-side from the whole session, so match around it.
    assert message.startswith("Serialized token too large for session. Token size of ") and message.endswith(
        " bytes exceeds the maximum allowed limit of 4096 bytes."
    ), message


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
