"""amr-provider-condition-admits-the-developer-provider-and-refuses-the-user-pool-login."""
from __future__ import annotations

import base64
import json
import time
import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "amr-provider-condition-admits-the-developer-provider-and-refuses-the-user-pool-login"
GROUP = "overly-permissive"
SERVICES = ["cognito-identity"]

_REFUSAL_CODE = "InvalidIdentityPoolConfigurationException"
_REFUSAL_MESSAGE = "Invalid identity pool configuration. Check assigned IAM roles for this pool."
_TRUST_BUDGET_S = 240.0
_TRANSIENT_SET_ROLES = (
    "AccessDenied", "AccessDeniedException", "InvalidParameterException",
    "ThrottlingException", "TooManyRequestsException", "ConcurrentModificationException",
)


def _poll_until(fn, pred, timeout_s=180.0, interval_s=5.0, description="condition"):
    """Poll fn() until pred(result) or the deadline; ClientErrors count as not-yet. Raises."""
    deadline = time.time() + timeout_s
    last = None
    last_exc = None
    while time.time() < deadline:
        try:
            last = fn()
            if pred(last):
                return last
            last_exc = None
        except ClientError as exc:
            last_exc = exc
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for {description}: last={last!r} err={last_exc!r}"
    )


def _decode_jwt_claims(token):
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def _amr_trust_policy(pool_id, amr_value):
    """Trust cognito-identity for this pool and ONLY logins whose amr contains *amr_value*."""
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                "ForAnyValue:StringLike": {
                    "cognito-identity.amazonaws.com:amr": amr_value
                },
            },
        }],
    })


def _create_role(iam, ctx, trust_policy, label):
    name = ctx.unique_name(f"sim2real-behav-{label}-")[:64]
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=trust_policy,
        Description="sim2real behavioral probe role for Cognito Identity",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return name, arn


def _set_roles(ci, pool_id, roles, timeout_s=180.0):
    """SetIdentityPoolRoles, retrying only the transient IAM-role-propagation rejections."""
    deadline = time.time() + timeout_s
    while True:
        try:
            return ci.set_identity_pool_roles(IdentityPoolId=pool_id, Roles=roles)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _TRANSIENT_SET_ROLES or time.time() >= deadline:
                raise
            time.sleep(3.0)


def _poll_for_role(ctx, ci, identity_id, logins_fn, expected_role_name, timeout_s, description):
    """Poll GetCredentialsForIdentity until the vended credentials resolve, at STS, to the role.

    After SetIdentityPoolRoles an identity can keep getting cached credentials for its old role.
    """

    def fn():
        creds = ci.get_credentials_for_identity(
            IdentityId=identity_id, Logins=logins_fn(),
        )["Credentials"]
        arn = _client_from_credentials(ctx, "sts", creds).get_caller_identity()["Arn"]
        return creds, arn

    return _poll_until(
        fn,
        lambda result: f":assumed-role/{expected_role_name}/" in result[1],
        timeout_s=timeout_s,
        description=description,
    )


def _developer_logins(ci, pool_id, identity_id, developer_provider, developer_user_id):
    """A fresh OpenID token for the developer identity, keyed `cognito-identity.amazonaws.com`.

    Only GetOpenIdTokenForDeveloperIdentity accepts the developer provider name as a Logins key.
    """
    token = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id,
        IdentityId=identity_id,
        Logins={developer_provider: developer_user_id},
    )["Token"]
    return {"cognito-identity.amazonaws.com": token}


def _client_from_credentials(ctx, service, creds):
    """Build a fresh client signed with the vended temporary credentials.

    Credentials are handed to the constructor by value and never written into os.environ.
    """
    return ctx.client(
        service,
        config=Config(retries={"max_attempts": 2}),
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds.get("SecretKey") or creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


# ===== check =====

@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An amr trust condition naming the developer provider vends the developer identity and refuses
    the user-pool identity, judged from the amr lists in the target's own tokens; a role trusting
    plain `authenticated` admits both.

    Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/iam-roles.html
    """
    ci = ctx.client("cognito-identity")
    idp = ctx.client("cognito-idp")
    iam = ctx.client("iam")

    # ---- a real user pool: the identity pool rejects fabricated third-party tokens.
    user_pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-amr-up-"),
        UserPoolTags={"sim2real": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=user_pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=user_pool_id,
        ClientName="sim2real-behav-amr-client",
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    provider = f"cognito-idp.{ctx.region}.amazonaws.com/{user_pool_id}"

    username = ctx.unique_name("sim2real-behav-amr-user-")
    password = "Sim2Real!" + uuid.uuid4().hex[:12]
    idp.admin_create_user(
        UserPoolId=user_pool_id, Username=username, MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(
        lambda: idp.admin_delete_user(UserPoolId=user_pool_id, Username=username)
    )
    idp.admin_set_user_password(
        UserPoolId=user_pool_id, Username=username, Password=password, Permanent=True,
    )
    id_token = idp.admin_initiate_auth(
        UserPoolId=user_pool_id, ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )["AuthenticationResult"]["IdToken"]
    user_pool_logins = {provider: id_token}

    # ---- one pool, two providers: a developer backend and the user pool.
    developer_provider = ctx.unique_name("sim2real.behav.amrdev.").replace("-", ".")[:100]
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_behav_amr_").replace("-", "_"),
        AllowUnauthenticatedIdentities=False,
        AllowClassicFlow=True,
        DeveloperProviderName=developer_provider,
        CognitoIdentityProviders=[{
            "ProviderName": provider,
            "ClientId": client_id,
            "ServerSideTokenCheck": False,
        }],
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    # ---- read the amr lists off the tokens the TARGET minted; every prediction below derives from
    # these two assertions.
    developer_user_id = ctx.unique_name("sim2real-behav-amrdevuser-")
    developer_token_response = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id,
        Logins={developer_provider: developer_user_id},
    )
    developer_identity = developer_token_response["IdentityId"]
    ctx.on_cleanup(
        lambda: ci.delete_identities(IdentityIdsToDelete=[developer_identity])
    )
    developer_amr = _decode_jwt_claims(developer_token_response["Token"]).get("amr") or []
    assert "authenticated" in developer_amr, (
        f"a developer-authenticated identity's token must carry amr 'authenticated', got "
        f"{developer_amr!r}"
    )
    assert developer_provider in developer_amr, (
        f"a developer-authenticated identity's token must carry the developer provider "
        f"{developer_provider!r} in amr — that is what a provider-scoped trust condition matches "
        f"on; got {developer_amr!r}"
    )

    user_pool_identity = ci.get_id(
        IdentityPoolId=pool_id, Logins=user_pool_logins,
    )["IdentityId"]
    ctx.on_cleanup(
        lambda: ci.delete_identities(IdentityIdsToDelete=[user_pool_identity])
    )
    assert user_pool_identity != developer_identity, (
        f"the developer login and the user-pool login collapsed onto one identity "
        f"{developer_identity!r}, so nothing below distinguishes them"
    )
    user_pool_amr = _decode_jwt_claims(
        ci.get_open_id_token(
            IdentityId=user_pool_identity, Logins=user_pool_logins,
        )["Token"]
    ).get("amr") or []
    assert "authenticated" in user_pool_amr, (
        f"a user-pool login's token must carry amr 'authenticated', got {user_pool_amr!r}"
    )
    assert developer_provider not in user_pool_amr, (
        f"a user-pool login must NOT carry the developer provider {developer_provider!r} in amr; "
        f"if it does, the provider-scoped condition below cannot discriminate at all. Got "
        f"{user_pool_amr!r}"
    )

    # ---- the two roles: one scoped to the developer provider, one to plain `authenticated`.
    scoped_name, scoped_arn = _create_role(
        iam, ctx, _amr_trust_policy(pool_id, developer_provider), "amr-scoped",
    )
    open_name, open_arn = _create_role(
        iam, ctx, _amr_trust_policy(pool_id, "authenticated"), "amr-open",
    )
    _set_roles(ci, pool_id, {"authenticated": scoped_arn})

    # ---- positive control: the provider named in the condition is admitted, read at STS.
    _developer_creds, developer_arn = _poll_for_role(
        ctx, ci, developer_identity,
        lambda: _developer_logins(
            ci, pool_id, developer_identity, developer_provider, developer_user_id
        ),
        scoped_name,
        timeout_s=_TRUST_BUDGET_S,
        description="the amr-scoped role to admit the developer provider it names",
    )
    assert f":assumed-role/{scoped_name}/" in developer_arn, (
        f"control: the developer login must assume {scoped_name}, got {developer_arn}"
    )

    # ---- exactly one thing differs — which provider the login came through — and the amr lists
    # asserted above are the whole reason this must be refused.
    try:
        leaked = ci.get_credentials_for_identity(
            IdentityId=user_pool_identity, Logins=user_pool_logins,
        )
    except ClientError as exc:
        err = exc.response.get("Error", {})
        code = err.get("Code")
        message = err.get("Message") or ""
    else:
        leaked_arn = _client_from_credentials(
            ctx, "sts", leaked["Credentials"]
        ).get_caller_identity()["Arn"]
        raise AssertionError(
            f"the pool's authenticated role trusts only amr {developer_provider!r}, and the "
            f"user-pool login's amr is {user_pool_amr!r} which does not contain it, yet the "
            f"user-pool identity was vended {leaked['Credentials']['AccessKeyId']!r} acting as "
            f"{leaked_arn}"
        )
    assert code == _REFUSAL_CODE, (
        f"expected {_REFUSAL_CODE} for a login whose amr {user_pool_amr!r} misses "
        f"the trusted value {developer_provider!r}, got {code!r}: {message!r}"
    )
    assert message == _REFUSAL_MESSAGE, (
        f"expected message {_REFUSAL_MESSAGE!r}, got {message!r}"
    )

    # ---- the effect is absent, read independently: the identity and its login are untouched.
    described = ci.describe_identity(IdentityId=user_pool_identity)
    assert provider in described["Logins"], (
        f"the refused vend must leave the user-pool login linked; DescribeIdentity reports "
        f"{described.get('Logins')!r}, expected it to contain {provider!r}"
    )

    # ---- the control leg: re-point the pool at the role trusting plain `authenticated`, and demand
    # that BOTH logins reach it. A target that refuses the user-pool identity for any other reason
    # fails here.
    _set_roles(ci, pool_id, {"authenticated": open_arn})
    _open_user_pool_creds, open_user_pool_arn = _poll_for_role(
        ctx, ci, user_pool_identity, lambda: user_pool_logins, open_name,
        timeout_s=_TRUST_BUDGET_S,
        description="the amr:authenticated role to admit the user-pool login",
    )
    assert f":assumed-role/{open_name}/" in open_user_pool_arn, (
        f"the user-pool login must reach {open_name} once the pool trusts plain "
        f"amr:authenticated — otherwise the refusal above was not about the provider; got "
        f"{open_user_pool_arn}"
    )
    _open_developer_creds, open_developer_arn = _poll_for_role(
        ctx, ci, developer_identity,
        lambda: _developer_logins(
            ci, pool_id, developer_identity, developer_provider, developer_user_id
        ),
        open_name,
        timeout_s=_TRUST_BUDGET_S,
        description="the amr:authenticated role to admit the developer login too",
    )
    assert f":assumed-role/{open_name}/" in open_developer_arn, (
        f"the developer login must also reach {open_name}, got {open_developer_arn}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
