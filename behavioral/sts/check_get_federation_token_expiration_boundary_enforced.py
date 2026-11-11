"""get-federation-token-expiration-boundary-enforced."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-federation-token-expiration-boundary-enforced"
GROUP = "visibility-timeout-ttl"
SERVICES = ["sts"]


@tags("axis:happy-path", "cap:c7", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """Federated credentials can call the policy-allowed ListBuckets immediately, Expiration is
    issue-time + 900 s, and DurationSeconds=899 fails ValidationError with the exact message.
    """
    user_creds, _ = _iam_user_creds(
        ctx,
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["sts:GetFederationToken", "s3:ListAllMyBuckets"], "Resource": "*"}],
        },
    )
    sts = ctx.client("sts", creds=user_creds)
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}],
    }
    before = datetime.now(timezone.utc)
    resp = sts.get_federation_token(
        Name=ctx.unique_name("fedttl-")[:32], Policy=json.dumps(policy), DurationSeconds=900
    )
    after = datetime.now(timezone.utc)
    creds = resp["Credentials"]
    expiration = creds["Expiration"]
    s3_client = _client_with_creds(ctx, "s3", creds)

    s3_client.list_buckets()

    # The 900 s minimum duration exceeds the check's time budget, so expiry is not waited out.
    assert before.timestamp() + 895 <= expiration.timestamp() <= after.timestamp() + 905, (
        f"Expiration {expiration} is not ~900s from issuance window [{before}, {after}]"
    )

    # botocore validates min=900 locally; disable client-side validation so 899 reaches STS.
    sts_unvalidated = ctx.client(
        "sts", config=Config(parameter_validation=False), creds=user_creds
    )
    floor_code, floor_message = _error(
        lambda: sts_unvalidated.get_federation_token(
            Name=ctx.unique_name("fedttl-short-")[:32], Policy=json.dumps(policy),
            DurationSeconds=899,
        )
    )
    assert floor_code == "ValidationError", (
        f"unexpected code: {floor_code}"
    )
    assert floor_message == (
        "1 validation error detected: Value '899' at 'durationSeconds' failed to satisfy "
        "constraint: Member must have value greater than or equal to 900"
    ), floor_message


def _client_with_creds(ctx, service: str, creds: dict):
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _error(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("call unexpectedly succeeded")


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
