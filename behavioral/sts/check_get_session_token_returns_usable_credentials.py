"""get-session-token-returns-usable-credentials."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-session-token-returns-usable-credentials"
GROUP = 'credential-issuance'
SERVICES = ['sts']

@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSessionToken credentials must authenticate as the SAME identity as the caller."""

    user_creds, _ = _iam_user_creds(ctx)
    sts = ctx.client("sts", creds=user_creds)

    def _client_with_credentials(service, creds):
        return ctx.client(service, creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds.get("SessionToken"),
        })

    original = sts.get_caller_identity()
    resp = sts.get_session_token(DurationSeconds=900)
    creds = resp["Credentials"]
    assert creds["SessionToken"], "GetSessionToken must return a session token"
    client = _client_with_credentials("sts", creds)
    identity = client.get_caller_identity()
    assert identity["Arn"] == original["Arn"], (identity["Arn"], original["Arn"])
    assert identity["Account"] == original["Account"], (identity["Account"], original["Account"])


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
