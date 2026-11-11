"""get-federation-token-duration-reflected-in-expiration."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-federation-token-duration-reflected-in-expiration"
GROUP = 'credential-issuance'
SERVICES = ['sts']

@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """GetFederationToken Expiration tracks DurationSeconds (900 s and 3600 s land ~2700 s apart),
    and the issued credentials authenticate via GetCallerIdentity as the federated user."""

    user_creds, _ = _iam_user_creds(
        ctx,
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["sts:GetFederationToken"], "Resource": "*"}],
        },
    )
    sts = ctx.client("sts", creds=user_creds)
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}],
    }

    before_short = datetime.now(timezone.utc)
    short_resp = sts.get_federation_token(
        Name=ctx.unique_name("sim2real-fed-a-"), Policy=json.dumps(policy), DurationSeconds=900
    )
    after_short = datetime.now(timezone.utc)
    short_creds = short_resp["Credentials"]

    before_long = datetime.now(timezone.utc)
    long_resp = sts.get_federation_token(
        Name=ctx.unique_name("sim2real-fed-b-"), Policy=json.dumps(policy), DurationSeconds=3600
    )
    after_long = datetime.now(timezone.utc)
    long_creds = long_resp["Credentials"]

    fed_client = _sts_client_with_creds(ctx, short_creds)
    identity = fed_client.get_caller_identity()
    assert identity["Arn"] == short_resp["FederatedUser"]["Arn"], (
        f"credentials issued for {short_resp['FederatedUser']['Arn']!r} resolved to "
        f"{identity['Arn']!r} instead"
    )

    short_exp = short_creds["Expiration"]
    assert (
        before_short.timestamp() + 900 - 5 <= short_exp.timestamp() <= after_short.timestamp() + 900 + 5
    ), f"900s Expiration {short_exp} not within issuance window [{before_short}, {after_short}] + 900s"

    long_exp = long_creds["Expiration"]
    assert (
        before_long.timestamp() + 3600 - 5 <= long_exp.timestamp() <= after_long.timestamp() + 3600 + 5
    ), f"3600s Expiration {long_exp} not within issuance window [{before_long}, {after_long}] + 3600s"

    # A fixed ~900 s answer would pass a single window; the delta proves DurationSeconds is used.
    observed_delta = (long_exp - short_exp).total_seconds()
    assert 2600 <= observed_delta <= 2800, (
        f"expected ~2700s more TTL for a 3600s request than a 900s request, got {observed_delta}s"
    )



def _sts_client_with_creds(ctx: Any, creds: dict) -> Any:
    return ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
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
