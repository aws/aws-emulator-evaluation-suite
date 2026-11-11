"""xsvc-cognito-identity-2-sstc-disabled-then-deleted-user-token-rejected-twin-pool-still-vends."""
from __future__ import annotations

import json
import time
import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cognito-identity-2-sstc-disabled-then-deleted-user-token-rejected-twin-pool-still-vends"
GROUP = "server-side-token-check"
SERVICES = ["cognito-identity", "cognito-idp"]

_PROPAGATION_S = 180.0
_TRANSIENT_SET_ROLES = (
    "AccessDenied", "AccessDeniedException", "InvalidParameterException",
    "ThrottlingException", "TooManyRequestsException", "ConcurrentModificationException",
)


def _poll_until(fn, pred, timeout_s=_PROPAGATION_S, interval_s=3.0, description="condition"):
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


def _poll_for_refusal(fn, timeout_s=_PROPAGATION_S, interval_s=3.0, description="refusal"):
    """Retry FOR a refusal and return its (code, message); a propagation window is the only
    reason it could be late."""
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        time.sleep(interval_s)
    raise AssertionError(f"{description} never arrived within {timeout_s}s; last success {last!r}")


def _error(fn):
    """The AWS error (code, message) fn() raises. An unexpected SUCCESS is raised, never returned."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _cognito_trust_policy(pool_id):
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "authenticated"},
            },
        }],
    })


def _client_from_credentials(ctx, service, creds):
    """A target client signed with the vended temporary credentials, passed by value only."""
    return ctx.client(
        service,
        config=Config(retries={"max_attempts": 2}),
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds.get("SecretKey") or creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _session_role(ctx, creds):
    return _client_from_credentials(ctx, "sts", creds).get_caller_identity()["Arn"]


def _vends(ci, identity_id, logins, description):
    return _poll_until(
        lambda: ci.get_credentials_for_identity(IdentityId=identity_id, Logins=logins),
        lambda r: bool(r.get("Credentials", {}).get("SessionToken")),
        description=description,
    )["Credentials"]


def _user_pool(ctx, idp):
    """A user pool, one app client and one confirmed user; returns (pool, client, user, mint)."""
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-xsvc-sstc-up-"), UserPoolTags={"sim2real": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id, ClientName="sim2real-xsvc-sstc-client", GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    username = ctx.unique_name("sim2real-xsvc-sstc-user-")
    password = "Sim2Real!" + uuid.uuid4().hex[:12]
    idp.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    # No separate user cleanup: run() deletes the user, and deleting the pool removes it anyway.
    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True,
    )

    def mint():
        return idp.admin_initiate_auth(
            UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )["AuthenticationResult"]["IdToken"]

    return pool_id, client_id, username, mint


def _twin_pool(ctx, ci, iam, provider, client_id, server_side_token_check):
    """An identity pool over the user pool, differing from its twin ONLY in ServerSideTokenCheck."""
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_xsvc_sstc_").replace("-", "_"),
        AllowUnauthenticatedIdentities=False,
        CognitoIdentityProviders=[{
            "ProviderName": provider, "ClientId": client_id,
            "ServerSideTokenCheck": server_side_token_check,
        }],
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    stored = ci.describe_identity_pool(IdentityPoolId=pool_id)["CognitoIdentityProviders"][0]
    assert stored.get("ServerSideTokenCheck") is server_side_token_check, (
        f"DescribeIdentityPool must echo ServerSideTokenCheck={server_side_token_check!r}, "
        f"got {stored.get('ServerSideTokenCheck')!r}"
    )
    label = "on" if server_side_token_check else "off"
    role_name = ctx.unique_name(f"sim2real-xsvc-sstc-{label}-")[:64]
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_cognito_trust_policy(pool_id),
        Description="sim2real cross-service probe role for Cognito Identity",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    deadline = time.time() + _PROPAGATION_S
    while True:
        try:
            ci.set_identity_pool_roles(IdentityPoolId=pool_id, Roles={"authenticated": role_arn})
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _TRANSIENT_SET_ROLES or time.time() >= deadline:
                raise
            time.sleep(3.0)
    return pool_id, role_name


def _identity(ctx, ci, pool_id, logins):
    identity_id = ci.get_id(IdentityPoolId=pool_id, Logins=logins)["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_id]))
    return identity_id


@tags("axis:rejection", "cap:c7", "concern:e2e", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """With ServerSideTokenCheck=True, a disabled then deleted user's ID token is refused
    NotAuthorizedException on GetCredentialsForIdentity and GetId while the identity survives;
    a twin pool with ServerSideTokenCheck=False still vends for the same token.
    """
    ci = ctx.client("cognito-identity")
    idp = ctx.client("cognito-idp")
    iam = ctx.client("iam")

    user_pool, client_id, username, mint = _user_pool(ctx, idp)
    provider = f"cognito-idp.{ctx.region}.amazonaws.com/{user_pool}"
    checked_pool, checked_role = _twin_pool(ctx, ci, iam, provider, client_id, True)
    unchecked_pool, unchecked_role = _twin_pool(ctx, ci, iam, provider, client_id, False)

    token = mint()
    logins = {provider: token}
    checked_id = _identity(ctx, ci, checked_pool, logins)
    unchecked_id = _identity(ctx, ci, unchecked_pool, logins)

    for ident, role, label in ((checked_id, checked_role, "SSTC=True"),
                               (unchecked_id, unchecked_role, "SSTC=False")):
        arn = _session_role(ctx, _vends(ci, ident, logins, f"the {label} pool to vend"))
        assert f":assumed-role/{role}/" in arn, f"control: {label} must vend {role!r}, got {arn!r}"

    # ---- step 1: disable. The checked pool stops vending.
    idp.admin_disable_user(UserPoolId=user_pool, Username=username)
    code, message = _poll_for_refusal(
        lambda: ci.get_credentials_for_identity(IdentityId=checked_id, Logins=logins),
        description="the SSTC=True refusal after AdminDisableUser",
    )
    assert code == "NotAuthorizedException", (
        f"SSTC=True must refuse a disabled user's token NotAuthorizedException, got {code!r}"
    )
    expected = "Token is inactive"
    assert message == expected, f"expected AWS's exact message {expected!r}, got {message!r}"

    # ---- step 2: delete. The user is gone from cognito-idp ...
    idp.admin_delete_user(UserPoolId=user_pool, Username=username)
    code, message = _error(lambda: idp.admin_get_user(UserPoolId=user_pool, Username=username))
    assert code == "UserNotFoundException", (
        f"AdminGetUser must report the deleted user UserNotFoundException, got {code!r}"
    )
    expected = "User does not exist."
    assert message == expected, f"expected AWS's exact message {expected!r}, got {message!r}"

    # ... and the checked pool still refuses, on both entry points.
    code, message = _error(lambda: ci.get_credentials_for_identity(IdentityId=checked_id, Logins=logins))
    assert code == "NotAuthorizedException", (
        f"SSTC=True must refuse a deleted user's token NotAuthorizedException, got {code!r}"
    )
    expected = "Token is inactive"
    assert message == expected, f"expected AWS's exact message {expected!r}, got {message!r}"
    code, message = _error(lambda: ci.get_id(IdentityPoolId=checked_pool, Logins=logins))
    assert code == "NotAuthorizedException", (
        f"SSTC=True GetId must refuse a deleted user's token NotAuthorizedException, got {code!r}"
    )
    expected = "Token is inactive"
    assert message == expected, f"expected AWS's exact message {expected!r}, got {message!r}"

    # ---- the refusal is a refusal to vend: cognito-identity's record is not cascaded away.
    described = ci.describe_identity(IdentityId=checked_id)
    assert described.get("Logins") == [provider], (
        f"deleting the user-pool user must not unlink the identity; DescribeIdentity reports "
        f"{described.get('Logins')!r}"
    )

    # Without the server-side check an ID token stays redeemable after the user is gone.
    arn = _session_role(ctx, _vends(ci, unchecked_id, logins, "the SSTC=False twin for a deleted user"))
    assert f":assumed-role/{unchecked_role}/" in arn, (
        f"the SSTC=False twin must still vend {unchecked_role!r} for the deleted user's token, "
        f"got {arn!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
