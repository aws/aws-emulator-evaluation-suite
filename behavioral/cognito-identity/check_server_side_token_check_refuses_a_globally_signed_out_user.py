"""server-side-token-check-refuses-a-globally-signed-out-user."""
from __future__ import annotations

import json
import time
import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-token-check-refuses-a-globally-signed-out-user"
GROUP = "server-side"
SERVICES = ["cognito-identity"]

#: Bounded budget for AdminUserGlobalSignOut to become visible to the identity pool's
#: server-side check. A global sign-out is a user-pool state change that the identity pool reads
#: on the next request, so this is a propagation window, not a fixed wait.
_SIGNOUT_BUDGET_S = 120.0
_POLL_INTERVAL_S = 5.0

_TRANSIENT_SET_ROLES = (
    "AccessDenied", "AccessDeniedException", "InvalidParameterException",
    "ThrottlingException", "TooManyRequestsException", "ConcurrentModificationException",
)


def _poll_until(fn, pred, timeout_s=180.0, interval_s=3.0, description="condition"):
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


def _cognito_trust_policy(pool_id):
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                "ForAnyValue:StringLike": {
                    "cognito-identity.amazonaws.com:amr": "authenticated"
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


def _client_from_credentials(ctx, service, creds):
    """A client on the target signed with the vended temporary credentials."""
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
    """With ServerSideTokenCheck=True a globally-signed-out user's unexpired ID token is refused
    with NotAuthorizedException, while a twin pool with the check off still vends for that token.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cognito-identitypool-cognitoidentityprovider.html
    """
    ci = ctx.client("cognito-identity")
    idp = ctx.client("cognito-idp")
    iam = ctx.client("iam")

    # ---- a real user pool: Cognito Identity rejects fabricated third-party tokens, so a genuine
    # user-pool JWT is the only self-contained login.
    user_pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-sstc-up-"),
        UserPoolTags={"sim2real": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=user_pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=user_pool_id,
        ClientName="sim2real-behav-sstc-client",
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    provider = f"cognito-idp.{ctx.region}.amazonaws.com/{user_pool_id}"

    username = ctx.unique_name("sim2real-behav-sstc-user-")
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

    def _mint_id_token():
        return idp.admin_initiate_auth(
            UserPoolId=user_pool_id, ClientId=client_id,
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )["AuthenticationResult"]["IdToken"]

    # ---- two identity pools over the SAME provider, differing in exactly one field
    def _pool(server_side_token_check):
        pool_id = ci.create_identity_pool(
            IdentityPoolName=ctx.unique_name("sim2real_behav_sstc_").replace("-", "_"),
            AllowUnauthenticatedIdentities=False,
            CognitoIdentityProviders=[{
                "ProviderName": provider,
                "ClientId": client_id,
                "ServerSideTokenCheck": server_side_token_check,
            }],
            IdentityPoolTags={"sim2real": CHECK},
        )["IdentityPoolId"]
        ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
        described = ci.describe_identity_pool(IdentityPoolId=pool_id)
        stored = described["CognitoIdentityProviders"][0]
        assert stored.get("ServerSideTokenCheck") is server_side_token_check, (
            f"DescribeIdentityPool must echo ServerSideTokenCheck="
            f"{server_side_token_check!r}, got {stored.get('ServerSideTokenCheck')!r}"
        )
        role_name, role_arn = _create_role(
            iam, ctx, _cognito_trust_policy(pool_id),
            "sstc-on" if server_side_token_check else "sstc-off",
        )
        _set_roles(ci, pool_id, {"authenticated": role_arn})
        return pool_id, role_name

    checked_pool, checked_role = _pool(True)
    unchecked_pool, unchecked_role = _pool(False)

    token = _mint_id_token()
    logins = {provider: token}

    checked_identity = ci.get_id(
        IdentityPoolId=checked_pool, Logins=logins,
    )["IdentityId"]
    ctx.on_cleanup(
        lambda: ci.delete_identities(IdentityIdsToDelete=[checked_identity])
    )
    unchecked_identity = ci.get_id(
        IdentityPoolId=unchecked_pool, Logins=logins,
    )["IdentityId"]
    ctx.on_cleanup(
        lambda: ci.delete_identities(IdentityIdsToDelete=[unchecked_identity])
    )

    # ---- beat 1: positive control. The SSTC=True pool vends for a signed-IN user, and the
    # session really is the role the pool selected (independent read at STS, a different
    # operation than the vend).
    checked_creds = _poll_until(
        lambda: ci.get_credentials_for_identity(
            IdentityId=checked_identity, Logins=logins,
        ),
        lambda r: "Credentials" in r and r["Credentials"].get("SessionToken"),
        timeout_s=180.0,
        description="the SSTC=True pool to vend for a signed-in user",
    )["Credentials"]
    checked_arn = _client_from_credentials(
        ctx, "sts", checked_creds
    ).get_caller_identity()["Arn"]
    assert f":assumed-role/{checked_role}/" in checked_arn, (
        f"control: the SSTC=True pool must vend {checked_role}, got {checked_arn}"
    )

    # ---- beat 2: break exactly one thing — the user is globally signed out. The token itself is
    # untouched: same bytes, same signature, same unexpired `exp`.
    idp.admin_user_global_sign_out(UserPoolId=user_pool_id, Username=username)

    # ---- beat 3: the specific refusal, bounded. A propagation window is the only reason the
    # refusal could be late, so retry FOR the refusal and raise if it never arrives.
    deadline = time.time() + _SIGNOUT_BUDGET_S
    refusal = None
    last_success = None
    while time.time() < deadline:
        try:
            last_success = ci.get_credentials_for_identity(
                IdentityId=checked_identity, Logins=logins,
            )
        except ClientError as exc:
            refusal = exc.response.get("Error", {})
            break
        time.sleep(_POLL_INTERVAL_S)
    assert refusal is not None, (
        f"ServerSideTokenCheck=True must stop vending for a globally-signed-out user within "
        f"{_SIGNOUT_BUDGET_S}s, but GetCredentialsForIdentity still returned "
        f"{(last_success or {}).get('Credentials', {}).get('AccessKeyId')!r}"
    )
    assert refusal.get("Code") == "NotAuthorizedException", (
        f"expected NotAuthorizedException from the SSTC=True pool for a signed-out user, "
        f"got {refusal!r}"
    )
    assert refusal.get("Message") == "Token is inactive", (
        f"expected the exact refusal message AWS returns, got {refusal.get('Message')!r}"
    )

    # ---- beat 4: the effect is absent, and the refusal mutated nothing. DescribeIdentity is an
    # independent read through a different operation: the identity must still exist with the same
    # login linked, so the refusal is a refusal to VEND and not a silent unlink.
    described_identity = ci.describe_identity(IdentityId=checked_identity)
    assert described_identity["IdentityId"] == checked_identity, (
        f"DescribeIdentity must still resolve {checked_identity}, got "
        f"{described_identity.get('IdentityId')!r}"
    )
    assert provider in described_identity["Logins"], (
        f"the refused vend must leave the login linked; DescribeIdentity reports Logins="
        f"{described_identity.get('Logins')!r}, expected it to contain {provider!r}"
    )

    # ---- beat 5: the demonstrated control, in the same instant, on the SAME token. If this
    # refuses too, the refusal above was about the token and not about ServerSideTokenCheck.
    unchecked_creds = ci.get_credentials_for_identity(
        IdentityId=unchecked_identity, Logins=logins,
    )["Credentials"]
    unchecked_arn = _client_from_credentials(
        ctx, "sts", unchecked_creds
    ).get_caller_identity()["Arn"]
    assert f":assumed-role/{unchecked_role}/" in unchecked_arn, (
        f"the SSTC=False twin must still vend {unchecked_role} for the same signed-out token — "
        f"otherwise the refusal above proves nothing about ServerSideTokenCheck; got "
        f"{unchecked_arn}"
    )

    # ---- beat 6: restore. A fresh authentication re-establishes the session, and the identical
    # call on the identical pool and identity succeeds again.
    # Each attempt signs in afresh: a token issued right at the global sign-out can stay
    # revoked, so only a later sign-in re-establishes the session.
    restored = _poll_until(
        lambda: ci.get_credentials_for_identity(
            IdentityId=checked_identity, Logins={provider: _mint_id_token()},
        ),
        lambda r: "Credentials" in r and r["Credentials"].get("SessionToken"),
        timeout_s=120.0,
        description="the SSTC=True pool to vend again after a fresh sign-in",
    )["Credentials"]
    restored_arn = _client_from_credentials(
        ctx, "sts", restored
    ).get_caller_identity()["Arn"]
    assert f":assumed-role/{checked_role}/" in restored_arn, (
        f"after a fresh sign-in the SSTC=True pool must vend {checked_role} again, got "
        f"{restored_arn}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
