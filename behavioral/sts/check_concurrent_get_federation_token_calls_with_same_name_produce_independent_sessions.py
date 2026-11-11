"""concurrent-get-federation-token-calls-with-same-name-produce-independent-sessions."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-get-federation-token-calls-with-same-name-produce-independent-sessions"
GROUP = "concurrency"
SERVICES = ["sts"]


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two simultaneous GetFederationToken calls that pass the identical federated-user Name mint
    independent, non-colliding credential sets (distinct access key / secret / session token)
    that both resolve to the same federated identity and are each independently usable."""
    iam = ctx.client("iam")
    sts_admin = ctx.client("sts")

    user_name = ctx.unique_name("sim2real-behav-fedtok-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])

    def _delete_user():
        for key in iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]:
            iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
        for pol in iam.list_attached_user_policies(UserName=user_name)["AttachedPolicies"]:
            iam.detach_user_policy(UserName=user_name, PolicyArn=pol["PolicyArn"])
        iam.delete_user(UserName=user_name)

    ctx.on_cleanup(_delete_user)

    # GetFederationToken must be called with long-term IAM *user* credentials (not a role
    # session, not root) -- provision a real user + key. Admin so the session policy below,
    # intersected with the user's identity policy, resolves to exactly what we pass.
    iam.attach_user_policy(UserName=user_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    key = iam.create_access_key(UserName=user_name)["AccessKey"]

    fed_client = ctx.client(
        "sts",
        creds={
            "aws_access_key_id": key["AccessKeyId"],
            "aws_secret_access_key": key["SecretAccessKey"],
        },
    )

    deadline = time.monotonic() + 30
    ready = False
    while time.monotonic() < deadline:
        try:
            fed_client.get_caller_identity()
            ready = True
            break
        except ClientError:
            time.sleep(1)
    assert ready, "new IAM user access key never became usable"

    federated_name = ctx.unique_name("fed-")[:32]
    session_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sts:GetCallerIdentity", "Resource": "*"}],
    })

    def _get_token():
        return fed_client.get_federation_token(
            Name=federated_name, Policy=session_policy, DurationSeconds=900
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_get_token)
        fut_b = pool.submit(_get_token)
        resp_a = fut_a.result()
        resp_b = fut_b.result()

    creds_a, creds_b = resp_a["Credentials"], resp_b["Credentials"]
    assert creds_a["AccessKeyId"] != creds_b["AccessKeyId"], (
        f"concurrent GetFederationToken calls collided on AccessKeyId: both={creds_a['AccessKeyId']!r}"
    )
    assert creds_a["SecretAccessKey"] != creds_b["SecretAccessKey"], (
        "concurrent GetFederationToken calls collided on SecretAccessKey"
    )
    assert creds_a["SessionToken"] != creds_b["SessionToken"], (
        "concurrent GetFederationToken calls collided on SessionToken"
    )

    user_a, user_b = resp_a["FederatedUser"], resp_b["FederatedUser"]
    assert user_a["Arn"] == user_b["Arn"], (
        f"same federated Name should yield the same FederatedUser.Arn: {user_a['Arn']!r} != {user_b['Arn']!r}"
    )
    assert user_a["FederatedUserId"] == user_b["FederatedUserId"], (
        f"same federated Name should yield the same FederatedUserId: "
        f"{user_a['FederatedUserId']!r} != {user_b['FederatedUserId']!r}"
    )
    assert federated_name in user_a["Arn"], (
        f"expected federated Name {federated_name!r} in FederatedUser.Arn, got {user_a['Arn']!r}"
    )

    client_a = _client_from_creds(ctx, sts_admin, creds_a)
    client_b = _client_from_creds(ctx, sts_admin, creds_b)
    identity_a = client_a.get_caller_identity()
    identity_b = client_b.get_caller_identity()

    # Both independently-issued credential sets resolve to the same federated identity...
    assert identity_a["Arn"] == user_a["Arn"] == identity_b["Arn"], (
        f"both credential sets should resolve to FederatedUser.Arn {user_a['Arn']!r} via an "
        f"independent GetCallerIdentity, got {identity_a['Arn']!r} and {identity_b['Arn']!r}"
    )
    assert identity_a["UserId"] == identity_b["UserId"] == user_a["FederatedUserId"], (
        f"both credential sets should resolve to FederatedUserId {user_a['FederatedUserId']!r} "
        f"via an independent GetCallerIdentity, got {identity_a['UserId']!r} and {identity_b['UserId']!r}"
    )
    # ...via genuinely distinct, non-colliding credentials (already asserted above).


def _client_from_creds(ctx, base_client, creds):
    return ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
