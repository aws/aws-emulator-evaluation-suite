"""get-session-token-duration-reflected-in-expiration."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-session-token-duration-reflected-in-expiration"
GROUP = 'credential-issuance'
SERVICES = ['sts']

@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSessionToken Expiration tracks DurationSeconds: 900 s and 3600 s requests land ~900 s
    and ~3600 s out, at least 2500 s apart, so a fixed 900 s answer fails."""

    user_creds, _ = _iam_user_creds(ctx)
    sts = ctx.client("sts", creds=user_creds)

    def issue(duration_seconds: int) -> float:
        before = datetime.datetime.now(datetime.timezone.utc)
        resp = sts.get_session_token(DurationSeconds=duration_seconds)
        after = datetime.datetime.now(datetime.timezone.utc)
        exp = resp["Credentials"]["Expiration"]
        assert exp.tzinfo is not None, f"Expiration must be timezone-aware, got {exp!r}"
        mid = before + (after - before) / 2
        return (exp - mid).total_seconds()

    delta_short = issue(900)
    delta_long = issue(3600)

    assert 870 <= delta_short <= 930, (
        f"expected Expiration ~900s out for DurationSeconds=900, got {delta_short}s"
    )
    assert 3570 <= delta_long <= 3630, (
        f"expected Expiration ~3600s out for DurationSeconds=3600, got {delta_long}s"
    )
    assert delta_long - delta_short >= 2500, (
        f"Expiration did not move with DurationSeconds: 900s -> {delta_short}s, "
        f"3600s -> {delta_long}s"
    )


def _iam_user_creds(ctx, policy=None):
    """A fresh IAM user's long-term access key (``creds`` for ctx.client) and the user's ARN.

    GetSessionToken and GetFederationToken require an IAM user's long-term credentials.
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
