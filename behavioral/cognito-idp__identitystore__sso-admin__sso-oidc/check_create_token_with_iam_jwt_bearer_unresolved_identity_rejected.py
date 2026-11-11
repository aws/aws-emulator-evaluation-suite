"""create-token-with-iam-jwt-bearer-unresolved-identity-rejected."""
from __future__ import annotations

import base64
import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-token-with-iam-jwt-bearer-unresolved-identity-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-idp", "identitystore", "sso-admin", "sso-oidc"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """CreateTokenWithIAM(jwt-bearer) for a Cognito ID token whose email claim matches no IAM
    Identity Center user is InvalidGrantException "Resource not found", while the identical
    setup for a Cognito user whose email DOES match one still issues a token (positive control)."""
    sso = ctx.client("sso-admin")
    sso_oidc = ctx.client("sso-oidc")
    instance_arn = _get_instance_arn(ctx)
    identity_store_id = sso.describe_instance(InstanceArn=instance_arn)["IdentityStoreId"]

    pool = _create_user_pool_and_client(ctx)
    password = "Sim2Real!Passw0rd1"

    matched_email = f"{ctx.unique_name('sim2real-behav-ssooidc-matched')}@example.com"
    matched_username = ctx.unique_name("sim2real-behav-cogu-matched-")
    _create_confirmed_user(ctx, pool["pool_id"], matched_username, password, matched_email)
    matched_user_id = _create_identity_store_user(ctx, identity_store_id, matched_email)

    unmatched_email = f"{ctx.unique_name('sim2real-behav-ssooidc-unmatched')}@example.com"
    unmatched_username = ctx.unique_name("sim2real-behav-cogu-unmatched-")
    _create_confirmed_user(ctx, pool["pool_id"], unmatched_username, password, unmatched_email)
    # Deliberately no identitystore user for unmatched_email: the one thing broken.

    tti_arn = sso.create_trusted_token_issuer(
        InstanceArn=instance_arn,
        Name=ctx.unique_name("sim2real-behav-tti-"),
        TrustedTokenIssuerType="OIDC_JWT",
        TrustedTokenIssuerConfiguration={
            "OidcJwtConfiguration": {
                "IssuerUrl": f"https://cognito-idp.{ctx.region}.amazonaws.com/{pool['pool_id']}",
                "ClaimAttributePath": "email",
                "IdentityStoreAttributePath": "emails.value",
                "JwksRetrievalOption": "OPEN_ID_DISCOVERY",
            }
        },
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )["TrustedTokenIssuerArn"]
    ctx.on_cleanup(lambda: sso.delete_trusted_token_issuer(TrustedTokenIssuerArn=tti_arn))

    app_arn = sso.create_application(
        InstanceArn=instance_arn,
        ApplicationProviderArn="arn:aws:sso::aws:applicationProvider/custom",
        Name=ctx.unique_name("sim2real-behav-app-"),
    )["ApplicationArn"]
    ctx.on_cleanup(lambda: sso.delete_application(ApplicationArn=app_arn))

    sso.put_application_assignment_configuration(ApplicationArn=app_arn, AssignmentRequired=False)
    sso.put_application_grant(
        ApplicationArn=app_arn,
        GrantType="urn:ietf:params:oauth:grant-type:jwt-bearer",
        Grant={
            "JwtBearer": {
                "AuthorizedTokenIssuers": [
                    {"TrustedTokenIssuerArn": tti_arn, "AuthorizedAudiences": [pool["client_id"]]}
                ]
            }
        },
    )
    sso.put_application_authentication_method(
        ApplicationArn=app_arn,
        AuthenticationMethodType="IAM",
        AuthenticationMethod={
            "Iam": {
                "ActorPolicy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
                            "Action": "sso-oauth:CreateTokenWithIAM",
                            "Resource": "*",
                        }
                    ],
                }
            }
        },
    )

    # Positive control first: proves the shared TTI/app/grant wiring genuinely works before the
    # unresolved-identity call is blamed on it.
    matched_token = _exchange_with_retry(ctx, sso_oidc, app_arn, pool, matched_username, password)
    matched_claims = _decode_jwt_claims(matched_token["idToken"])
    assert matched_claims["sub"] == matched_user_id, (
        f"positive control: expected idToken sub={matched_user_id!r}, got {matched_claims.get('sub')!r}"
    )

    code, message = _exchange_expect_error(ctx, sso_oidc, app_arn, pool, unmatched_username, password)
    assert code == "InvalidGrantException", f"expected InvalidGrantException, got {code!r}"
    assert message == "Resource not found", f"unexpected message: {message!r}"


# ===== helpers =====


def _get_instance_arn(ctx) -> str:
    """The account's IAM Identity Center instance. One that already exists is reused and never
    deleted; when there is none, the check creates one and its cleanup deletes exactly that one,
    which restores the prior state (no instance)."""
    sso = ctx.client("sso-admin")
    instances = sso.list_instances().get("Instances", [])
    if instances:
        instance_arn = instances[0]["InstanceArn"]
    else:
        instance_arn = sso.create_instance()["InstanceArn"]
        ctx.on_cleanup(lambda: sso.delete_instance(InstanceArn=instance_arn))
    deadline = time.time() + 120
    status = None
    while time.time() < deadline:
        status = sso.describe_instance(InstanceArn=instance_arn)["Status"]
        if status == "ACTIVE":
            return instance_arn
        if status in ("CREATE_FAILED", "DELETE_IN_PROGRESS"):
            raise RuntimeError(f"IAM Identity Center instance in unexpected state: {status}")
        time.sleep(3)
    raise RuntimeError(f"IAM Identity Center instance did not become ACTIVE in time (last status: {status})")


def _create_user_pool_and_client(ctx) -> dict[str, str]:
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-ssooidc-pool-"),
        UserPoolTags={"sim2real-behav": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    client = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-ssooidc-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]
    client_id = client["ClientId"]
    ctx.on_cleanup(lambda: idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    return {"pool_id": pool_id, "client_id": client_id}


def _create_confirmed_user(ctx, pool_id: str, username: str, password: str, email: str) -> None:
    idp = ctx.client("cognito-idp")
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=password,
        MessageAction="SUPPRESS",
        UserAttributes=[
            {"Name": "email", "Value": email},
            {"Name": "email_verified", "Value": "true"},
        ],
    )
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)


def _authenticate(ctx, pool_id: str, client_id: str, username: str, password: str) -> dict[str, Any]:
    idp = ctx.client("cognito-idp")
    resp = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return resp["AuthenticationResult"]


def _create_identity_store_user(ctx, identity_store_id: str, email: str) -> str:
    idstore = ctx.client("identitystore")
    username = ctx.unique_name("sim2real-behav-idcu-")
    user_id = idstore.create_user(
        IdentityStoreId=identity_store_id,
        UserName=username,
        DisplayName=username,
        Name={"GivenName": "Sim2Real", "FamilyName": "User"},
        Emails=[{"Value": email, "Primary": True}],
    )["UserId"]
    ctx.on_cleanup(lambda: idstore.delete_user(IdentityStoreId=identity_store_id, UserId=user_id))
    return user_id


def _exchange_with_retry(ctx, sso_oidc, app_arn: str, pool: dict[str, str], username: str, password: str) -> dict[str, Any]:
    """The trusted token issuer, grant and actor policy just configured may take a few seconds
    to take effect. Each attempt mints a fresh Cognito ID token, since a JWT-bearer assertion
    is single-use."""
    deadline = time.monotonic() + 90.0
    while True:
        id_token = _authenticate(ctx, pool["pool_id"], pool["client_id"], username, password)["IdToken"]
        try:
            return sso_oidc.create_token_with_iam(
                clientId=app_arn,
                grantType="urn:ietf:params:oauth:grant-type:jwt-bearer",
                assertion=id_token,
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("InvalidClientException", "AccessDeniedException") or time.monotonic() >= deadline:
                raise
            time.sleep(3)


def _exchange_expect_error(ctx, sso_oidc, app_arn: str, pool: dict[str, str], username: str, password: str) -> tuple[str, str]:
    """Like `_exchange_with_retry`, but the only acceptable terminal outcome is a rejection: an
    unexpected SUCCESS raises rather than silently passing."""
    deadline = time.monotonic() + 90.0
    while True:
        id_token = _authenticate(ctx, pool["pool_id"], pool["client_id"], username, password)["IdToken"]
        try:
            result = sso_oidc.create_token_with_iam(
                clientId=app_arn,
                grantType="urn:ietf:params:oauth:grant-type:jwt-bearer",
                assertion=id_token,
            )
        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "")
            if code in ("InvalidClientException", "AccessDeniedException") and time.monotonic() < deadline:
                time.sleep(3)
                continue
            return code, error.get("Message", "")
        raise AssertionError(
            f"expected a rejection, but the call SUCCEEDED and returned keys {sorted(result)!r}"
        )


def _decode_jwt_claims(token: str) -> dict[str, Any]:
    payload_b64 = token.split(".")[1]
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
