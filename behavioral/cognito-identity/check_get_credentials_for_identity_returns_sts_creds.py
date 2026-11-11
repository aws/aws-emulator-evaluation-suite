"""get-credentials-for-identity-returns-sts-creds."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "get-credentials-for-identity-returns-sts-creds"
GROUP = "roles"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """End-to-end: with a real IAM role wired via SetIdentityPoolRoles, GetCredentialsForIdentity
    performs the AssumeRoleWithWebIdentity exchange and returns usable, correctly-scoped
    temporary AWS credentials for the identity's own account/role."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    ci = ctx.client("cognito-identity")

    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-"),
        AllowUnauthenticatedIdentities=True,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    role_name = ctx.unique_name("sim2real-behav-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                        "ForAnyValue:StringLike": {
                            "cognito-identity.amazonaws.com:amr": "unauthenticated"
                        },
                    },
                }
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust_policy
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    ci.set_identity_pool_roles(IdentityPoolId=pool_id, Roles={"unauthenticated": role_arn})

    identity_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_id]))

    account_id = sts.get_caller_identity()["Account"]

    creds = _poll_until(
        lambda: ci.get_credentials_for_identity(IdentityId=identity_id),
        lambda resp: resp is not None,
        timeout_s=90.0,
        interval_s=5.0,
    )
    assert creds is not None, "GetCredentialsForIdentity never succeeded (IAM role propagation?)"
    assert creds["IdentityId"] == identity_id
    c = creds["Credentials"]
    assert c["AccessKeyId"].startswith("AS"), f"unexpected access key form: {c['AccessKeyId']!r}"
    assert c["SecretKey"]
    assert c["SessionToken"]
    exp = c["Expiration"]
    if isinstance(exp, (int, float)):
        exp = datetime.fromtimestamp(exp, tz=timezone.utc)
    assert exp > datetime.now(timezone.utc), "Expiration must be in the future"

    # The vended credentials must actually work and resolve to the trusted role, in our account.
    # Re-signed via ctx.client(creds=...) so this second hop still lands on the target under test
    # (real AWS or an emulator), not a hardcoded real-AWS endpoint.
    caller = ctx.client(
        "sts",
        creds={
            "aws_access_key_id": c["AccessKeyId"],
            "aws_secret_access_key": c["SecretKey"],
            "aws_session_token": c["SessionToken"],
        },
    ).get_caller_identity()
    assert caller["Account"] == account_id
    assert role_name in caller["Arn"], f"assumed identity {caller['Arn']!r} doesn't reference {role_name!r}"


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = probe()
        except ClientError:
            last = None
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
