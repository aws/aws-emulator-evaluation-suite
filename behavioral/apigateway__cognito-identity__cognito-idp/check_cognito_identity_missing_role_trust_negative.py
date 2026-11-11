"""cognito-identity-missing-role-trust-negative."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cognito-identity-missing-role-trust-negative"
GROUP = "overly-permissive"
SERVICES = ["apigateway", "cognito-identity", "cognito-idp"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetCredentialsForIdentity fails with InvalidIdentityPoolConfigurationException and no credentials when the
    mapped role does not trust cognito-identity.amazonaws.com; re-pointing the pool at a trusted role succeeds."""
    pool = _create_confirmed_user_pool(ctx, "sim2real-uidpt-")
    identity_pool_id = _create_identity_pool(
        ctx,
        "sim2real-ipt-",
        providers=[
            {
                "ProviderName": pool["provider_name"],
                "ClientId": pool["client_id"],
                "ServerSideTokenCheck": False,
            }
        ],
    )
    untrusted_role = _create_role(ctx, identity_pool_id, amr="authenticated", trust_cognito=False)

    cid = ctx.client("cognito-identity")
    cid.set_identity_pool_roles(
        IdentityPoolId=identity_pool_id, Roles={"authenticated": untrusted_role["arn"]}
    )

    logins = {pool["provider_name"]: pool["id_token"]}
    identity_id = cid.get_id(IdentityPoolId=identity_pool_id, Logins=logins)["IdentityId"]

    code, message = _error(
        lambda: cid.get_credentials_for_identity(IdentityId=identity_id, Logins=logins)
    )
    assert code == "InvalidIdentityPoolConfigurationException", (
        f"expected InvalidIdentityPoolConfigurationException for an untrusted mapped role, got {code!r}"
    )
    want_message = "Invalid identity pool configuration. Check assigned IAM roles for this pool."
    assert message == want_message, (
        f"expected the refusal message {want_message!r}, got {message!r}"
    )

    # Positive control: same identity pool + same identity, role trust policy fixed.
    trusted_role = _create_role(ctx, identity_pool_id, amr="authenticated", trust_cognito=True)
    cid.set_identity_pool_roles(
        IdentityPoolId=identity_pool_id, Roles={"authenticated": trusted_role["arn"]}
    )
    creds = _get_credentials_with_retry(ctx, identity_id, logins)["Credentials"]

    # Independent read at the destination: the vended credentials must actually work,
    # not merely contain non-empty strings — assume the identity using them and confirm
    # STS resolves the caller back to the role this check just trusted.
    caller_arn = _client_from_credentials(ctx, "sts", creds).get_caller_identity()["Arn"]
    assert f":assumed-role/{trusted_role['name']}/" in caller_arn, (
        f"expected credentials assuming {trusted_role['name']!r} after restoring trust, "
        f"got caller identity {caller_arn!r}"
    )


def _client_from_credentials(ctx, service, creds):
    """A target-wired client signed with vended temporary credentials, passed explicitly so
    nothing else in the process can pick them up via the ambient chain."""
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds.get("SecretKey") or creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _error(fn) -> tuple[str, str]:
    """The (code, message) of the AWS error ``fn`` raised; raises when the call succeeded."""
    try:
        fn()
    except ClientError as e:
        error = e.response.get("Error", {})
        return error.get("Code", ""), error.get("Message", "")
    raise AssertionError("the call SUCCEEDED; real AWS refuses it, so there is no code to assert")


def _create_confirmed_user_pool(ctx, name_prefix: str) -> dict:
    idp = ctx.client("cognito-idp")
    pool_name = ctx.unique_name(name_prefix)
    pool_id = idp.create_user_pool(
        PoolName=pool_name, UserPoolTags={"sim2real": CHECK}
    )["UserPool"]["Id"]
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
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: cid.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


def _create_role(ctx, identity_pool_id: str, amr: str, trust_cognito: bool) -> dict:
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
