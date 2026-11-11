"""get-federation-token-returns-federated-user."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-federation-token-returns-federated-user"
GROUP = 'credential-issuance'
SERVICES = ['sts']

def _client_with_creds(ctx, service: str, creds: dict):
    """A client for *service* on the target, signed with the given temporary credentials."""
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded poll to a condition; raises on deadline miss."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not reached within {timeout_s}s; last observed: {last!r}"
            )
        time.sleep(interval_s)

@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetFederationToken returns a FederatedUser whose Arn and Id embed Name, and
    GetCallerIdentity through the minted credentials reports that same Arn and UserId."""

    user_creds, _ = _iam_user_creds(
        ctx,
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sts:GetFederationToken", "Resource": "*"}],
        },
    )
    sts = ctx.client("sts", creds=user_creds)

    name = ctx.unique_name("sim2real-behav-fed-")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}],
    }

    def _mint():
        try:
            return sts.get_federation_token(
                Name=name, Policy=json.dumps(policy), DurationSeconds=3600
            )
        except ClientError as exc:
            # The user's just-attached policy is eventually consistent: retry until the deadline.
            return exc.response.get("Error", {}).get("Message")

    left = ctx.time_left()
    resp = _poll_until(
        _mint,
        lambda r: isinstance(r, dict),
        timeout_s=60.0 if left is None else min(60.0, max(left - 30.0, 0.0)),
        interval_s=2.0,
        description="the IAM user's sts:GetFederationToken permission took effect",
    )
    fed = resp["FederatedUser"]
    assert fed["Arn"].endswith(f"federated-user/{name}"), (
        f"FederatedUser.Arn must embed the requested Name {name!r}; got {fed['Arn']!r}"
    )
    assert fed["FederatedUserId"].endswith(f":{name}"), (
        f"FederatedUser.FederatedUserId must embed the requested Name {name!r}; "
        f"got {fed['FederatedUserId']!r}"
    )
    creds = resp["Credentials"]
    assert creds.get("SessionToken"), "GetFederationToken must return a non-empty SessionToken"

    probe = _client_with_creds(ctx, "sts", creds)

    def _try_identity():
        try:
            return probe.get_caller_identity()
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    identity = _poll_until(
        _try_identity,
        lambda r: isinstance(r, dict),
        timeout_s=60.0, interval_s=2.0,
        description="minted federation-token credentials became usable via GetCallerIdentity",
    )
    assert identity["Arn"] == fed["Arn"], (
        "GetCallerIdentity through the minted credentials must report the SAME Arn "
        f"GetFederationToken promised; expected {fed['Arn']!r}, got {identity['Arn']!r}"
    )
    assert identity["UserId"] == fed["FederatedUserId"], (
        "GetCallerIdentity's UserId must equal the FederatedUserId GetFederationToken "
        f"promised; expected {fed['FederatedUserId']!r}, got {identity['UserId']!r}"
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
