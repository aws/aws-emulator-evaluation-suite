"""get-session-token-expiration-timestamp-precision-preserved."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-session-token-expiration-timestamp-precision-preserved"
GROUP = "representation"
SERVICES = ["sts"]


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSessionToken's Credentials.Expiration is a UTC whole-second timestamp (no sub-second
    part, no float drift) that lands at issuance time + DurationSeconds."""
    user_creds, _ = _iam_user_creds(ctx)
    sts = ctx.client("sts", creds=user_creds)

    duration_seconds = 900  # minimum allowed value
    before = datetime.now(timezone.utc)
    creds = sts.get_session_token(DurationSeconds=duration_seconds)["Credentials"]
    after = datetime.now(timezone.utc)
    expiration = creds["Expiration"]

    assert expiration.tzinfo is not None, (
        f"expected Expiration to be timezone-aware, got naive datetime {expiration!r}"
    )
    assert expiration.utcoffset().total_seconds() == 0, (
        f"expected Expiration offset 0 (UTC), got offset {expiration.utcoffset()} on {expiration!r}"
    )

    # STS truncates Expiration to the whole second on the wire.
    assert expiration.microsecond == 0, (
        f"expected Expiration microsecond=0 (whole-second precision), got "
        f"microsecond={expiration.microsecond} on {expiration!r}"
    )

    # Catches float drift in a round trip even when microsecond reads as 0.
    epoch = expiration.timestamp()
    assert epoch == int(epoch), (
        f"expected Expiration epoch to be an exact whole second with no float drift, "
        f"got epoch={epoch!r}"
    )

    # Window of +/-5s absorbs request/response latency.
    lower_bound = before + timedelta(seconds=duration_seconds - 5)
    upper_bound = after + timedelta(seconds=duration_seconds + 5)
    assert lower_bound <= expiration <= upper_bound, (
        f"expected Expiration in [{lower_bound!r}, {upper_bound!r}] for "
        f"DurationSeconds={duration_seconds}, got {expiration!r}"
    )


def _iam_user_creds(ctx, policy=None):
    """A fresh IAM user's long-term access key (``creds`` for ctx.client) and the user's ARN.

    GetSessionToken requires an IAM user's long-term credentials.
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
