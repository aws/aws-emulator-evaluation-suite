"""xsvc-cognito-identity-2-sstc-disabled-user-token-rejected-and-stays-revoked-after-enable."""
from __future__ import annotations

import json
import time
import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cognito-identity-2-sstc-disabled-user-token-rejected-and-stays-revoked-after-enable"
GROUP = "server-side-token-check"
SERVICES = ["cognito-identity", "cognito-idp"]

_PROPAGATION_S = 180.0
_TRANSIENT_SET_ROLES = (
    "AccessDenied", "AccessDeniedException", "InvalidParameterException",
    "ThrottlingException", "TooManyRequestsException", "ConcurrentModificationException",
)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, fn, pred, timeout_s=_PROPAGATION_S, interval_s=1.0, description="condition"):
    """Poll fn() until pred(result) or the deadline; ClientErrors count as not-yet. Raises."""
    timeout_s = _budget_s(ctx, timeout_s)
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
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for {description}: last={last!r} err={last_exc!r}"
    )


def _poll_for_refusal(ctx, fn, timeout_s=_PROPAGATION_S, interval_s=1.0, description="refusal"):
    """Retry FOR a refusal and return its (code, message); a propagation window is the only
    reason it could be late."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
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


def _vends(ctx, ci, identity_id, logins, description):
    """Poll until a vend succeeds; a callable `logins` is re-evaluated on every attempt."""
    return _poll_until(
        ctx,
        lambda: ci.get_credentials_for_identity(
            IdentityId=identity_id, Logins=logins() if callable(logins) else logins,
        ),
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
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))
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
    deadline = time.time() + _budget_s(ctx, _PROPAGATION_S)
    while True:
        try:
            ci.set_identity_pool_roles(IdentityPoolId=pool_id, Roles={"authenticated": role_arn})
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _TRANSIENT_SET_ROLES or time.time() >= deadline:
                if code in _TRANSIENT_SET_ROLES and _budget_spent(ctx):
                    raise TimeoutError("SetIdentityPoolRoles past role propagation: the run budget ended first; not graded") from exc
                raise
            time.sleep(1.0)
    return pool_id, role_name


def _identity(ctx, ci, pool_id, logins):
    identity_id = ci.get_id(IdentityPoolId=pool_id, Logins=logins)["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_id]))
    return identity_id


@tags("axis:rejection", "cap:c7", "concern:e2e", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AdminDisableUser revokes an outstanding ID token at a ServerSideTokenCheck=True pool
    (NotAuthorizedException on vend and GetId) while an SSTC=False twin still vends for it;
    re-enabling lets a fresh token vend but does not resurrect the revoked one.
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

    # ---- positive controls: both pools vend for the enabled user.
    for ident, role, label in ((checked_id, checked_role, "SSTC=True"),
                               (unchecked_id, unchecked_role, "SSTC=False")):
        arn = _session_role(ctx, _vends(ctx, ci, ident, logins, f"the {label} pool to vend"))
        assert f":assumed-role/{role}/" in arn, f"control: {label} must vend {role!r}, got {arn!r}"

    # ---- break exactly one thing: the user is disabled. The token bytes are untouched.
    idp.admin_disable_user(UserPoolId=user_pool, Username=username)
    enabled = idp.admin_get_user(UserPoolId=user_pool, Username=username)["Enabled"]
    assert enabled is False, f"AdminGetUser must report Enabled=False after the disable, got {enabled!r}"

    code, message = _poll_for_refusal(
        ctx, lambda: ci.get_credentials_for_identity(IdentityId=checked_id, Logins=logins),
        description="the SSTC=True refusal for a disabled user's token",
    )
    assert code == "NotAuthorizedException", (
        f"SSTC=True must refuse a disabled user's token NotAuthorizedException, got {code!r}"
    )
    expected = "Token is inactive"
    assert message == expected, f"expected AWS's exact message {expected!r}, got {message!r}"
    code, message = _error(lambda: ci.get_id(IdentityPoolId=checked_pool, Logins=logins))
    assert code == "NotAuthorizedException", (
        f"SSTC=True GetId must refuse a disabled user's token NotAuthorizedException, got {code!r}"
    )
    expected = "Token is inactive"
    assert message == expected, f"expected AWS's exact message {expected!r}, got {message!r}"

    # ---- the demonstrated control, same token, same instant.
    arn = _session_role(ctx, _vends(ctx, ci, unchecked_id, logins, "the SSTC=False twin for the disabled user"))
    assert f":assumed-role/{unchecked_role}/" in arn, (
        f"the SSTC=False twin must still vend {unchecked_role!r} for the same token, got {arn!r}"
    )

    # ---- re-enable: a fresh token vends on the checked pool, proving the enable took effect ...
    idp.admin_enable_user(UserPoolId=user_pool, Username=username)
    arn = _session_role(ctx, _vends(ctx, ci, checked_id, lambda: {provider: mint()},
                                    "a fresh token after AdminEnableUser"))
    assert f":assumed-role/{checked_role}/" in arn, (
        f"after AdminEnableUser a fresh token must vend {checked_role!r}, got {arn!r}"
    )
    # ... while the token outstanding at disable time stays revoked.
    code, message = _error(lambda: ci.get_credentials_for_identity(IdentityId=checked_id, Logins=logins))
    assert code == "NotAuthorizedException", (
        f"AdminEnableUser must not resurrect the token revoked by AdminDisableUser; the SSTC=True "
        f"pool returned {code!r}"
    )
    expected = "Token is inactive"
    assert message == expected, f"expected AWS's exact message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
