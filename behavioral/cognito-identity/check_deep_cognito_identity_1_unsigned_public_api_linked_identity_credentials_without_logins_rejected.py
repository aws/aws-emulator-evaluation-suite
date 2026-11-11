"""deep-cognito-identity-1-unsigned-public-api-linked-identity-credentials-without-logins-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cognito-identity-1-unsigned-public-api-linked-identity-credentials-without-logins-rejected"
GROUP = "unsigned-public-api"
SERVICES = ["cognito-identity"]

# On real Cognito Identity, an UNSIGNED GetCredentialsForIdentity
# for an identity that carries a federated login, sent WITHOUT that login, is refused
# NotAuthorizedException ("Access to Identity '...' is forbidden."); with the login it vends the
# AUTHENTICATED role. The pool also allows unauthenticated identities and has an unauth role.
ERR_NOT_AUTHORIZED = "NotAuthorizedException"
_PROPAGATION_CODES = {"InvalidIdentityPoolConfigurationException"}


@tags(
    "dp:api",
    "plane:data",
    "concern:negative-classes",
    "concern:data-plane",
    "axis:rejection",
    "cap:c1",
)
def run(ctx) -> None:
    """An unsigned GetCredentialsForIdentity without Logins is refused for a login-bearing
    identity, while with the login it vends the authenticated role and an anonymous identity in
    the same pool gets the unauthenticated role."""
    signed = ctx.client("cognito-identity")
    unsigned = ctx.client("cognito-identity", config=Config(signature_version=UNSIGNED))
    iam = ctx.client("iam")
    me = ctx.client("sts").get_caller_identity()
    account, partition = me["Account"], me["Arn"].split(":")[1]

    idp, user_pool_id, client_id = _create_user_pool(ctx)
    provider = f"cognito-idp.{ctx.region}.amazonaws.com/{user_pool_id}"
    id_token = _mint_id_token(idp, ctx, user_pool_id, client_id)
    pool_id = _create_identity_pool(signed, ctx, provider, client_id)

    auth_role = _create_role(ctx, iam, pool_id, "authenticated")
    unauth_role = _create_role(ctx, iam, pool_id, "unauthenticated")
    signed.set_identity_pool_roles(IdentityPoolId=pool_id, Roles={
        "authenticated": f"arn:{partition}:iam::{account}:role/{auth_role}",
        "unauthenticated": f"arn:{partition}:iam::{account}:role/{unauth_role}",
    })

    linked = unsigned.get_id(IdentityPoolId=pool_id, Logins={provider: id_token})["IdentityId"]

    # Positive control first, so IAM propagation cannot be mistaken for the refusal below.
    with_login = _poll_until_success(
        lambda: unsigned.get_credentials_for_identity(IdentityId=linked, Logins={provider: id_token}),
        retryable_codes=_PROPAGATION_CODES, timeout_s=120.0, interval_s=3.0,
    )
    arn = _caller_arn(ctx, with_login["Credentials"])
    want = f"arn:{partition}:sts::{account}:assumed-role/{auth_role}/"
    assert arn.startswith(want), f"credentials vended WITH the login are {arn!r}; expected {want}*"

    err = _error(lambda: unsigned.get_credentials_for_identity(IdentityId=linked))
    expected = (ERR_NOT_AUTHORIZED, f"Access to Identity '{linked}' is forbidden.")
    assert (err.get("Code"), err.get("Message")) == expected, (
        f"unsigned GetCredentialsForIdentity for a linked identity without Logins answered "
        f"{err!r}, expected {expected!r}"
    )
    still = signed.describe_identity(IdentityId=linked).get("Logins")
    assert still == [provider], (
        f"the refused call changed the identity's Logins to {still!r}, expected [{provider!r}]"
    )

    anon = unsigned.get_id(IdentityPoolId=pool_id)["IdentityId"]
    assert anon != linked, f"anonymous GetId returned the linked identity {linked!r}"
    anon_creds = _poll_until_success(
        lambda: unsigned.get_credentials_for_identity(IdentityId=anon),
        retryable_codes=_PROPAGATION_CODES, timeout_s=120.0, interval_s=3.0,
    )
    anon_arn = _caller_arn(ctx, anon_creds["Credentials"])
    want_anon = f"arn:{partition}:sts::{account}:assumed-role/{unauth_role}/"
    assert anon_arn.startswith(want_anon), (
        f"anonymous identity's credentials are {anon_arn!r}; expected {want_anon}*"
    )


# ===== helpers =====

def _caller_arn(ctx, creds):
    return ctx.client("sts", creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretKey"],
        "aws_session_token": creds["SessionToken"],
    }).get_caller_identity()["Arn"]


def _create_role(ctx, iam, pool_id, amr):
    """A role with the trust policy shape AWS documents for an identity pool `amr` role."""
    name = ctx.unique_name(f"sim2real-unsigned-{amr[:5]}-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": amr},
            },
        }],
    }
    iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": GROUP}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return name


def _error(fn):
    """The ClientError fn() raised (Code, Message). A success is never an error: it raises instead."""
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    resp.pop("ResponseMetadata", None)
    raise AssertionError(f"call was expected to be refused but succeeded: {resp!r}")


def _poll_until_success(fn, *, retryable_codes, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in retryable_codes:
                raise
            last = exc
            time.sleep(interval_s)
    raise AssertionError(f"never succeeded within {timeout_s}s: {last}")


def _create_identity_pool(ci, ctx, provider, client_id):
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-unsigned-pool-").replace("-", "_"),
        AllowUnauthenticatedIdentities=True,
        CognitoIdentityProviders=[{
            "ProviderName": provider, "ClientId": client_id, "ServerSideTokenCheck": False,
        }],
        IdentityPoolTags={"sim2real": GROUP},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


def _create_user_pool(ctx):
    """A real user pool + app client: Cognito Identity rejects fabricated provider tokens."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-unsigned-up-"), UserPoolTags={"sim2real": GROUP},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName="sim2real-unsigned-client",
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    return idp, pool_id, client_id


def _mint_id_token(idp, ctx, pool_id, client_id):
    username = ctx.unique_name("sim2real-unsigned-user-")
    password = "Sim2Real!" + uuid.uuid4().hex[:12]
    idp.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))
    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True,
    )
    auth = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return auth["AuthenticationResult"]["IdToken"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
