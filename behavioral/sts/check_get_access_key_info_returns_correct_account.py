"""get-access-key-info-returns-correct-account."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-access-key-info-returns-correct-account"
GROUP = 'credential-issuance'
SERVICES = ['sts']

@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAccessKeyInfo must report the account that owns the given access key."""

    sts = ctx.client("sts")
    user_creds, _ = _iam_user_creds(ctx)

    identity = sts.get_caller_identity()
    resp = ctx.client("sts", creds=user_creds).get_session_token()
    access_key_id = resp["Credentials"]["AccessKeyId"]
    assert access_key_id.startswith("ASIA"), (
        f"expected a temporary (ASIA) access key id from GetSessionToken, got {access_key_id[:4]!r}"
    )

    info = sts.get_access_key_info(AccessKeyId=access_key_id)
    assert info["Account"] == identity["Account"], (info, identity)
    assert info["Account"].isdigit() and len(info["Account"]) == 12, (
        f"expected a 12-digit decimal account id, got {info['Account']!r}"
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
