"""get-federation-token-name-special-chars-preserved-in-arn."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-federation-token-name-special-chars-preserved-in-arn"
GROUP = "representation"
SERVICES = ["sts"]


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A GetFederationToken Name using the allowed special characters ``+=,.@-`` is preserved in
    FederatedUser.Arn and FederatedUserId, and GetCallerIdentity echoes the same ARN.
    """
    user_creds, _ = _iam_user_creds(
        ctx,
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["sts:GetFederationToken"], "Resource": "*"}],
        },
    )
    sts = ctx.client("sts", creds=user_creds)
    suffix = uuid.uuid4().hex[:6]
    name = f"sim2real+A=B,C.D@E-{suffix}"
    assert 2 <= len(name) <= 32, f"test-constructed name {name!r} violates userNameType length bounds"

    account = sts.get_caller_identity()["Account"]
    resp = sts.get_federation_token(Name=name)
    federated_user = resp["FederatedUser"]
    assert federated_user["Arn"].endswith(f"federated-user/{name}"), (
        f"expected Arn to end with 'federated-user/{name}', got {federated_user['Arn']!r}"
    )
    assert federated_user["FederatedUserId"] == f"{account}:{name}", (
        f"expected FederatedUserId {account}:{name!r}, got {federated_user['FederatedUserId']!r}"
    )

    identity = _client_with_creds(ctx, "sts", resp["Credentials"]).get_caller_identity()
    assert identity["Arn"] == federated_user["Arn"], (
        f"expected GetCallerIdentity Arn to echo {federated_user['Arn']!r}, got {identity['Arn']!r}"
    )


def _client_with_creds(ctx, service: str, creds: dict):
    return ctx.client(
        service,
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
