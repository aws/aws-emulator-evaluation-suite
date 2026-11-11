"""get-caller-identity-account-id-matches-across-credential-types-workflow."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "get-caller-identity-account-id-matches-across-credential-types-workflow"
GROUP = "data-plane"
SERVICES = ["sts"]
_MANAGED_TAG_KEY = "sim2real:managed"


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCallerIdentity reports the same Account whether the caller's credentials came
    from a plain IAM user, AssumeRole, GetSessionToken, or GetFederationToken, all minted
    from one IAM principal."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    user_name = ctx.unique_name("sim2real-behav-xcred-")
    iam.create_user(
        UserName=user_name, Tags=[{"Key": _MANAGED_TAG_KEY, "Value": "true"}]
    )
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    user_arn = f"arn:aws:iam::{account_id}:user/{user_name}"

    role_name = ctx.unique_name("sim2real-behav-xcred-role-")
    role_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": user_arn},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = _create_role_with_new_principal(
        iam, role_name, json.dumps(role_trust), tags=[{"Key": _MANAGED_TAG_KEY, "Value": "true"}]
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "sim2real-behav-xcred-policy"
    user_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["sts:AssumeRole", "sts:GetFederationToken", "sts:GetSessionToken"],
                "Resource": "*",
            }
        ],
    }
    iam.put_user_policy(
        UserName=user_name, PolicyName=policy_name, PolicyDocument=json.dumps(user_policy)
    )
    ctx.on_cleanup(
        lambda: iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)
    )

    access_key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(
            UserName=user_name, AccessKeyId=access_key["AccessKeyId"]
        )
    )
    user_creds = {
        "AccessKeyId": access_key["AccessKeyId"],
        "SecretAccessKey": access_key["SecretAccessKey"],
    }
    base_client = _client_with_creds(ctx, "sts", user_creds)
    _wait_for_new_credentials(base_client)

    baseline = base_client.get_caller_identity()
    assert baseline["Account"] == account_id, baseline
    partition = sts.get_caller_identity()["Arn"].split(":")[1]
    user_arn = f"arn:{partition}:iam::{account_id}:user/{user_name}"
    assert baseline["Arn"] == user_arn, f"expected Arn {user_arn!r} for the IAM user's own keys: {baseline}"

    assumed_creds = _wait_for_assume_role(
        base_client, RoleArn=role_arn, RoleSessionName="xcred-assume"
    )
    assumed_identity = _client_with_creds(ctx, "sts", assumed_creds).get_caller_identity()
    assert assumed_identity["Account"] == account_id, assumed_identity
    assumed_arn = f"arn:{partition}:sts::{account_id}:assumed-role/{role_name}/xcred-assume"
    assert assumed_identity["Arn"] == assumed_arn, (
        f"expected Arn {assumed_arn!r} for AssumeRole credentials: {assumed_identity}"
    )
    assert assumed_identity["UserId"].endswith(":xcred-assume"), (
        f"expected UserId '<role id>:xcred-assume' for AssumeRole credentials: {assumed_identity}"
    )

    fed_name = ctx.unique_name("xcredfed-")[:32]
    fed_creds = base_client.get_federation_token(Name=fed_name)["Credentials"]
    fed_identity = _client_with_creds(ctx, "sts", fed_creds).get_caller_identity()
    assert fed_identity["Account"] == account_id, fed_identity
    fed_arn = f"arn:{partition}:sts::{account_id}:federated-user/{fed_name}"
    assert fed_identity["Arn"] == fed_arn, (
        f"expected Arn {fed_arn!r} for GetFederationToken credentials: {fed_identity}"
    )
    assert fed_identity["UserId"] == f"{account_id}:{fed_name}", (
        f"expected UserId {account_id}:{fed_name!r} for GetFederationToken credentials: {fed_identity}"
    )

    session_creds = base_client.get_session_token()["Credentials"]
    session_identity = _client_with_creds(ctx, "sts", session_creds).get_caller_identity()
    assert session_identity["Account"] == account_id, session_identity
    assert session_identity["Arn"] == user_arn, (
        f"expected GetSessionToken credentials to keep the IAM user's Arn {user_arn!r}: {session_identity}"
    )
    assert session_identity["UserId"] == baseline["UserId"], (
        f"expected GetSessionToken credentials to keep the IAM user's UserId "
        f"{baseline['UserId']!r}: {session_identity}"
    )


def _create_role_with_new_principal(
    iam_client,
    role_name: str,
    trust_policy_json: str,
    tags: list[dict[str, str]] | None = None,
    timeout_s: float = 20.0,
    interval_s: float = 2.0,
) -> str:
    """Create a role trusting a just-created principal, polling past the transient
    MalformedPolicyDocument ("Invalid principal in policy") while that principal propagates."""
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            kwargs: dict[str, Any] = {
                "RoleName": role_name,
                "AssumeRolePolicyDocument": trust_policy_json,
            }
            if tags:
                kwargs["Tags"] = tags
            return iam_client.create_role(**kwargs)["Role"]["Arn"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "MalformedPolicyDocument":
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"create_role never accepted the new principal within {timeout_s}s: {last_err}")


def _client_with_creds(ctx, service: str, creds: dict[str, Any]):
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds.get("SessionToken"),
        },
    )


def _wait_for_new_credentials(sts_client, timeout_s: float = 30.0, interval_s: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            sts_client.get_caller_identity()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code not in ("InvalidClientTokenId", "AccessDenied"):
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"new access key never became active within {timeout_s}s: {last_err}")


def _wait_for_assume_role(sts_client, timeout_s: float = 30.0, interval_s: float = 2.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return sts_client.assume_role(**kwargs)["Credentials"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "AccessDenied":
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"assume_role never became permitted within {timeout_s}s: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
