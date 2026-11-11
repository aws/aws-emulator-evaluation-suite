"""cognito-identity-get-credentials-for-identity-positive."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cognito-identity-get-credentials-for-identity-positive"
GROUP = "triggers"
SERVICES = ["apigateway", "cognito-identity", "cognito-idp"]


@tags("axis:happy-path", "cap:c7", "concern:e2e", "plane:control")
def run(ctx) -> None:
    """GetCredentialsForIdentity with a valid User Pool token exchanges the identity for
    temporary STS credentials scoped to the identity pool's mapped authenticated role."""
    pool = _create_confirmed_user_pool(ctx, "sim2real-uidp2-")
    identity_pool_id = _create_identity_pool(
        ctx,
        "sim2real-ip2-",
        providers=[
            {
                "ProviderName": pool["provider_name"],
                "ClientId": pool["client_id"],
                "ServerSideTokenCheck": False,
            }
        ],
    )
    role = _create_federated_role(ctx, identity_pool_id, amr="authenticated")

    cid = ctx.client("cognito-identity")
    cid.set_identity_pool_roles(
        IdentityPoolId=identity_pool_id, Roles={"authenticated": role["arn"]}
    )

    logins = {pool["provider_name"]: pool["id_token"]}
    identity_id = cid.get_id(IdentityPoolId=identity_pool_id, Logins=logins)["IdentityId"]

    creds_resp = _get_credentials_with_retry(ctx, identity_id, logins)
    creds = creds_resp["Credentials"]
    assert creds_resp["IdentityId"] == identity_id, (
        f"expected IdentityId {identity_id!r}, got {creds_resp['IdentityId']!r}"
    )
    assert creds["AccessKeyId"] and creds["SecretKey"] and creds["SessionToken"], (
        f"incomplete credentials in GetCredentialsForIdentity response: {creds!r}"
    )

    # Same target as every other client in this check; only the credentials differ.
    borrowed_sts = ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    caller = borrowed_sts.get_caller_identity()
    # arn:aws:sts::<account>:assumed-role/<role-name>/<session>
    assumed_role_name = caller["Arn"].split(":assumed-role/", 1)[1].split("/", 1)[0]
    assert assumed_role_name == role["name"], (
        f"expected the vended credentials to assume role {role['name']!r}, "
        f"got {assumed_role_name!r} (caller arn={caller['Arn']!r})"
    )


def _create_confirmed_user_pool(ctx, name_prefix: str) -> dict:
    idp = ctx.client("cognito-idp")
    pool_name = ctx.unique_name(name_prefix)
    pool_id = idp.create_user_pool(PoolName=pool_name)["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=pool_name + "-client",
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("user-")
    password = "Sim2Real1!Aa"
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=password,
        MessageAction="SUPPRESS",
    )
    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )
    auth = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    id_token = auth["AuthenticationResult"]["IdToken"]
    provider_name = f"cognito-idp.{ctx.region}.amazonaws.com/{pool_id}"
    return {
        "pool_id": pool_id,
        "client_id": client_id,
        "username": username,
        "id_token": id_token,
        "provider_name": provider_name,
    }


def _create_identity_pool(ctx, name_prefix: str, providers=None, allow_unauth: bool = False) -> str:
    cid = ctx.client("cognito-identity")
    name = ctx.unique_name(name_prefix)
    pool_id = cid.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=allow_unauth,
        CognitoIdentityProviders=providers or [],
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: cid.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


def _create_federated_role(ctx, identity_pool_id: str, amr: str, trust_cognito: bool = True) -> dict:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cidp-role-")
    if trust_cognito:
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
    else:
        trust_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_doc)
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
