"""federation-token-credentials-expiration-anchored-to-requested-duration."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "federation-token-credentials-expiration-anchored-to-requested-duration"
GROUP = "visibility-timeout-ttl"
SERVICES = ["sts"]


@tags("axis:happy-path", "cap:c7", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """GetFederationToken credentials authenticate as the federated user immediately, Expiration
    is issue-time + 900 s, and DurationSeconds=500 fails ValidationError with the exact message.
    """
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
        "Statement": [{"Effect": "Allow", "Action": "sts:GetCallerIdentity", "Resource": "*"}],
    }
    before = datetime.now(timezone.utc)
    resp = sts.get_federation_token(
        Name=ctx.unique_name("fed-user-")[:32],
        Policy=json.dumps(policy),
        DurationSeconds=900,
    )
    after = datetime.now(timezone.utc)
    creds = resp["Credentials"]
    federated_arn = resp["FederatedUser"]["Arn"]
    fed_client = _sts_client_with_creds(ctx, creds)

    identity = fed_client.get_caller_identity()
    assert identity["Arn"] == federated_arn, (
        f"federated credentials authenticated as {identity['Arn']!r}, expected {federated_arn!r}"
    )

    expiration = creds["Expiration"]
    assert before.timestamp() + 900 - 5 <= expiration.timestamp() <= after.timestamp() + 900 + 5, (
        f"Expiration {expiration} is not requested-duration-900s from issuance "
        f"window [{before}, {after}]"
    )

    # botocore validates min=900 locally; disable client-side validation so 500 reaches STS.
    sts_unvalidated = ctx.client(
        "sts", config=Config(parameter_validation=False), creds=user_creds
    )
    code, message = _client_error(lambda: sts_unvalidated.get_federation_token(
        Name=ctx.unique_name("fed-user-")[:32], Policy=json.dumps(policy), DurationSeconds=500
    ))
    assert code == "ValidationError", f"unexpected code: {code}"
    assert message == (
        "1 validation error detected: Value '500' at 'durationSeconds' failed to satisfy "
        "constraint: Member must have value greater than or equal to 900"
    ), message



def _sts_client_with_creds(ctx: Any, creds: dict) -> Any:
    return ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _client_error(fn) -> tuple[str, str]:
    """The (code, message) of the ClientError ``fn`` raises; an unexpected success fails loudly."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("call unexpectedly succeeded")


def _iam_user_creds(ctx, policy=None):
    """A fresh IAM user's long-term access key (``creds`` for ctx.client) and the user's ARN.

    GetFederationToken requires an IAM user's long-term credentials.
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

