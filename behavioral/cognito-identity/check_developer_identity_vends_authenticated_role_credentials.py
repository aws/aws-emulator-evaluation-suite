"""developer-identity-vends-authenticated-role-credentials."""
from __future__ import annotations

import base64
import json
import time
import uuid
from datetime import datetime, timezone

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "developer-identity-vends-authenticated-role-credentials"
GROUP = 'developer-identity'
SERVICES = ['cognito-identity']



def _poll_until(fn, pred, timeout_s=180.0, interval_s=3.0, description="condition"):
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


def _decode_jwt_claims(token):
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def _create_identity_pool(ci, ctx, allow_unauth=True, **kwargs):
    name = ctx.unique_name("sim2real-behav-cip-").replace("-", "_")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=allow_unauth,
        **kwargs,
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


def _cognito_trust_policy(pool_id, amr=None):
    condition = {"StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id}}
    if amr:
        condition["ForAnyValue:StringLike"] = {"cognito-identity.amazonaws.com:amr": amr}
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": condition,
        }],
    })


def _create_role(iam, ctx, trust_policy, label):
    name = ctx.unique_name(f"sim2real-behav-{label}-")[:64]
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust_policy)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return name, arn


_TRANSIENT_SET_ROLES = (
    "AccessDenied", "AccessDeniedException", "InvalidParameterException",
    "ThrottlingException", "TooManyRequestsException", "ConcurrentModificationException",
)


def _set_roles(ci, pool_id, roles, role_mappings=None, timeout_s=180.0):
    """SetIdentityPoolRoles, retrying only the transient IAM-role-propagation rejections."""
    kwargs = {"IdentityPoolId": pool_id, "Roles": roles}
    if role_mappings is not None:
        kwargs["RoleMappings"] = role_mappings
    deadline = time.time() + timeout_s
    while True:
        try:
            return ci.set_identity_pool_roles(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _TRANSIENT_SET_ROLES or time.time() >= deadline:
                raise
            time.sleep(3.0)


def _client_from_credentials(ctx, service, creds):
    """Build a client signed with the vended temporary credentials, never via os.environ."""
    return ctx.client(
        service,
        config=Config(retries={"max_attempts": 2}),
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds.get("SecretKey") or creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )



@tags("axis:happy-path", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A developer identity's OpenID token under the cognito-identity.amazonaws.com login key vends
    authenticated-role credentials while a guest gets the unauthenticated role; the same token
    keyed by the developer provider name is rejected."""
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")

    developer_provider = "sim2real-behav-dev-" + uuid.uuid4().hex[:8]
    pool_id = _create_identity_pool(
        ci, ctx, allow_unauth=True, DeveloperProviderName=developer_provider,
    )
    described = ci.describe_identity_pool(IdentityPoolId=pool_id)
    assert described.get("DeveloperProviderName") == developer_provider, (
        f"DescribeIdentityPool must echo DeveloperProviderName={developer_provider!r}, got "
        f"{described.get('DeveloperProviderName')!r}"
    )

    trust = _cognito_trust_policy(pool_id)
    unauth_name, unauth_arn = _create_role(iam, ctx, trust, "unauth")
    auth_name, auth_arn = _create_role(iam, ctx, trust, "auth")
    _set_roles(ci, pool_id, {"authenticated": auth_arn, "unauthenticated": unauth_arn})

    developer_user_id = "sim2real-behav-user-" + uuid.uuid4().hex[:12]
    minted = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id,
        Logins={developer_provider: developer_user_id},
        TokenDuration=900,
    )
    identity_id = minted["IdentityId"]
    token = minted["Token"]

    claims = _decode_jwt_claims(token)
    assert claims.get("sub") == identity_id, (
        f"the developer token's sub must be the IdentityId {identity_id}, got {claims.get('sub')!r}"
    )
    assert claims.get("aud") == pool_id, (
        f"the developer token's aud must be the identity pool {pool_id}, got {claims.get('aud')!r}"
    )
    assert "authenticated" in claims.get("amr", []), (
        f"a developer-authenticated identity must carry amr=authenticated, got "
        f"{claims.get('amr')!r}"
    )

    creds = _poll_until(
        lambda: ci.get_credentials_for_identity(
            IdentityId=identity_id,
            Logins={"cognito-identity.amazonaws.com": token},
        ),
        lambda r: "Credentials" in r and r["Credentials"].get("SessionToken"),
        description="the developer identity to be vended credentials",
    )["Credentials"]
    assert creds["AccessKeyId"].startswith("ASIA"), (
        f"vended AccessKeyId {creds['AccessKeyId']} is not an ASIA session key"
    )
    assert creds["SecretKey"] and creds["SessionToken"], (
        f"incomplete credential envelope: {sorted(creds)}"
    )
    assert creds["Expiration"] > datetime.now(timezone.utc), (
        f"credential Expiration {creds['Expiration']} is not in the future"
    )
    caller_arn = _client_from_credentials(ctx, "sts", creds).get_caller_identity()["Arn"]
    assert f":assumed-role/{auth_name}/" in caller_arn, (
        f"a developer-authenticated identity must assume the authenticated role {auth_name}, got "
        f"{caller_arn}"
    )

    # Contrast: an anonymous identity in the same pool lands on the unauthenticated role.
    guest_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    guest_creds = _poll_until(
        lambda: ci.get_credentials_for_identity(IdentityId=guest_id),
        lambda r: "Credentials" in r and r["Credentials"].get("SessionToken"),
        description="the guest identity to be vended credentials",
    )["Credentials"]
    guest_arn = _client_from_credentials(ctx, "sts", guest_creds).get_caller_identity()["Arn"]
    assert f":assumed-role/{unauth_name}/" in guest_arn, (
        f"a guest identity must assume the unauthenticated role {unauth_name}, got {guest_arn}"
    )

    # Break exactly one thing: present the same valid token under the developer provider name
    # instead of the reserved cognito-identity.amazonaws.com key.
    err = None
    try:
        response = ci.get_credentials_for_identity(
            IdentityId=identity_id, Logins={developer_provider: token},
        )
    except ClientError as exc:
        err = exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(
            "a developer token keyed by the developer provider name is not a valid login and "
            f"must be rejected, but credentials were vended: "
            f"{response.get('Credentials', {}).get('AccessKeyId')!r}"
        )
    expected = ("InvalidParameterException", "Please provide a valid public provider")
    assert err == expected, (
        f"expected {expected!r} for a token under the developer provider key, got {err!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
