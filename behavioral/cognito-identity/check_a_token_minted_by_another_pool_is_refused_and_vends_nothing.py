"""a-token-minted-by-another-pool-is-refused-and-vends-nothing."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "a-token-minted-by-another-pool-is-refused-and-vends-nothing"
GROUP = 'overly-permissive'
SERVICES = ['cognito-identity']

# A token minted by a different identity pool is refused with NotAuthorizedException
# "Invalid login token. Not a Cognito token."
EXPECTED_CODE = "NotAuthorizedException"
EXPECTED_MESSAGE = "Invalid login token. Not a Cognito token."
DEVELOPER_TOKEN_LOGIN = "cognito-identity.amazonaws.com"
_TRANSIENT_SET_ROLES = (
    "AccessDenied", "AccessDeniedException", "InvalidParameterException",
    "ThrottlingException", "TooManyRequestsException", "ConcurrentModificationException",
)


def _poll_until(fn, pred, timeout_s=120.0, interval_s=3.0, description="condition"):
    """Poll fn() until pred(result) or the deadline; ClientErrors count as not-yet."""
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


def _refusal(fn):
    """Call fn(); return (result, Code, Message). Exactly one of result / Code is set, so a call
    that must be refused and was not surfaces as a result rather than as a missing code."""
    try:
        return fn(), None, None
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return None, err.get("Code"), err.get("Message") or ""


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


def _pool_with_authenticated_role(ci, iam, ctx, label):
    """A pool with a developer provider and an authenticated role it can actually vend, so a
    refusal below cannot be confused with the InvalidIdentityPoolConfigurationException a
    role-less pool raises. Returns (pool_id, developer_provider, role_name)."""
    developer_provider = ctx.unique_name(f"sim2real-behav-{label}-dev-")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name(f"sim2real_behav_{label}_").replace("-", "_"),
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=developer_provider,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    role_name = ctx.unique_name(f"sim2real-behav-{label}-role-")[:64]
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id}
                },
            }],
        }),
        Description="sim2real behavioral probe role for Cognito Identity",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    _set_roles(ci, pool_id, {"authenticated": role_arn})
    return pool_id, developer_provider, role_name


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetCredentialsForIdentity with an OpenID token minted by another pool is refused with
    NotAuthorizedException, vends nothing and leaves the target's logins unchanged, while each
    pool's own token vends credentials for its own identity."""
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")

    target_pool, target_provider, target_role_name = _pool_with_authenticated_role(
        ci, iam, ctx, "target"
    )
    foreign_pool, foreign_provider, _ = _pool_with_authenticated_role(
        ci, iam, ctx, "foreign"
    )
    assert target_pool != foreign_pool, f"both pools resolved to {target_pool!r}"

    target_user = ctx.unique_name("sim2real-behav-target-user-")
    target_token = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=target_pool, Logins={target_provider: target_user}
    )
    target_identity = target_token["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[target_identity]))

    foreign_user = ctx.unique_name("sim2real-behav-foreign-user-")
    foreign_token = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=foreign_pool, Logins={foreign_provider: foreign_user}
    )
    foreign_identity = foreign_token["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[foreign_identity]))

    # ---- break exactly one thing: the token belongs to the other pool
    vended, code, message = _refusal(lambda: ci.get_credentials_for_identity(
        IdentityId=target_identity,
        Logins={DEVELOPER_TOKEN_LOGIN: foreign_token["Token"]},
    ))
    assert code is not None, (
        f"a token minted by pool {foreign_pool!r} must not vend credentials for an identity in "
        f"pool {target_pool!r}, but the call returned {vended!r}"
    )
    assert code == EXPECTED_CODE, (
        f"expected {EXPECTED_CODE!r} for a foreign-pool token, got {code!r}: {message!r}"
    )
    assert message == EXPECTED_MESSAGE, (message, EXPECTED_MESSAGE)
    assert vended is None, (
        f"credentials were vended for a foreign-pool token: {vended!r}"
    )

    # ---- the effect is absent: the target identity did not acquire the foreign login
    target_logins = ci.describe_identity(IdentityId=target_identity).get("Logins", [])
    assert foreign_provider not in target_logins, (
        f"the target identity's logins were {target_logins!r}; the refused call attached the "
        f"foreign provider {foreign_provider!r}"
    )
    assert target_logins == [target_provider], (
        f"the target identity's logins changed across the refused call: {target_logins!r}, "
        f"expected exactly [{target_provider!r}]"
    )

    # ---- positive control 1: that token IS valid, for its own pool
    foreign_creds = _poll_until(
        lambda: ci.get_credentials_for_identity(
            IdentityId=foreign_identity,
            Logins={DEVELOPER_TOKEN_LOGIN: foreign_token["Token"]},
        ),
        lambda r: "Credentials" in r and r["Credentials"].get("SessionToken"),
        description="the foreign token to vend credentials against its own pool",
    )["Credentials"]
    assert foreign_creds.get("AccessKeyId"), (
        f"the token was rejected by its own pool too, so nothing above is evidence about "
        f"cross-pool binding: {foreign_creds!r}"
    )

    # ---- positive control 2: the target pool vends for its own token, as its own role
    target_creds_resp = _poll_until(
        lambda: ci.get_credentials_for_identity(
            IdentityId=target_identity,
            Logins={DEVELOPER_TOKEN_LOGIN: target_token["Token"]},
        ),
        lambda r: "Credentials" in r and r["Credentials"].get("SessionToken"),
        description="the target pool's own token to vend credentials",
    )
    assert target_creds_resp["IdentityId"] == target_identity, (
        f"the target pool vended credentials for {target_creds_resp['IdentityId']!r}, expected "
        f"{target_identity!r}"
    )
    assert set(target_creds_resp["Credentials"]) >= {
        "AccessKeyId", "SecretKey", "SessionToken"
    }, (
        f"incomplete credentials from the same-pool call: "
        f"{sorted(target_creds_resp['Credentials'])!r}"
    )
    roles = ci.get_identity_pool_roles(IdentityPoolId=target_pool)["Roles"]
    assert roles["authenticated"].split("/")[-1] == target_role_name, (
        f"the target pool's authenticated role is {roles['authenticated']!r}, expected "
        f"{target_role_name!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
