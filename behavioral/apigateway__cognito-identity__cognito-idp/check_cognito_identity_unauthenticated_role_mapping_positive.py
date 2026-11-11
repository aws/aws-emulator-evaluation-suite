"""cognito-identity-unauthenticated-role-mapping-positive."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cognito-identity-unauthenticated-role-mapping-positive"
GROUP = "triggers"
SERVICES = ["apigateway", "cognito-identity", "cognito-idp"]


@tags("axis:happy-path", "cap:c7", "concern:e2e", "plane:control")
def run(ctx) -> None:
    """GetCredentialsForIdentity called with NO login providers returns credentials
    scoped to the identity pool's configured unauthenticated role, not the authenticated one."""
    identity_pool_id = _create_identity_pool(ctx, "sim2real-ipu-", allow_unauth=True)
    unauth_role = _create_federated_role(ctx, identity_pool_id, amr="unauthenticated")

    cid = ctx.client("cognito-identity")
    cid.set_identity_pool_roles(
        IdentityPoolId=identity_pool_id, Roles={"unauthenticated": unauth_role["arn"]}
    )

    identity_id = cid.get_id(IdentityPoolId=identity_pool_id)["IdentityId"]
    assert identity_id.startswith(f"{ctx.region}:"), (
        f"expected identity id prefixed with region {ctx.region!r}, got {identity_id!r}"
    )

    creds = _get_credentials_with_retry(ctx, identity_id)["Credentials"]
    borrowed_sts = ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    caller = borrowed_sts.get_caller_identity()
    assumed_role_name = caller["Arn"].split(":assumed-role/", 1)[1].split("/", 1)[0]
    assert assumed_role_name == unauth_role["name"], (
        f"expected credentials scoped to unauthenticated role {unauth_role['name']!r}, "
        f"got assumed-role identity {caller['Arn']!r}"
    )


def _create_identity_pool(ctx, name_prefix: str, providers=None, allow_unauth: bool = False) -> str:
    cid = ctx.client("cognito-identity")
    name = ctx.unique_name(name_prefix)
    pool_id = cid.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=allow_unauth,
        CognitoIdentityProviders=providers or [],
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: cid.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


def _create_federated_role(ctx, identity_pool_id: str, amr: str) -> dict:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cidp-role-")
    trust_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": identity_pool_id},
                    "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": amr},
                },
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_doc),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return {"name": role_name, "arn": role_arn}


def _get_credentials_with_retry(ctx, identity_id: str, logins=None, timeout_s=45.0, interval_s=3.0):
    cid = ctx.client("cognito-identity")
    kwargs = {"IdentityId": identity_id}
    if logins:
        kwargs["Logins"] = logins
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return cid.get_credentials_for_identity(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidIdentityPoolConfigurationException":
                raise
            last_exc = e
            time.sleep(interval_s)
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
