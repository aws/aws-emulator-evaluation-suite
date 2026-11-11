"""unauthenticated-upgrade-keeps-the-identity-but-the-guest-role-is-denied-the-privileged-prefix."""
from __future__ import annotations

import json
import time
import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unauthenticated-upgrade-keeps-the-identity-but-the-guest-role-is-denied-the-privileged-prefix"
GROUP = 'overly-permissive'
SERVICES = ['cognito-identity']

# On real AWS, passing an existing anonymous IdentityId to
# GetOpenIdTokenForDeveloperIdentity attaches the developer login to THAT identity and returns the
# same IdentityId, so the guest and the logged-in user really are one identity.
DENIED_CODE = "AccessDenied"
DEVELOPER_TOKEN_LOGIN = "cognito-identity.amazonaws.com"
_TRANSIENT_SET_ROLES = (
    "AccessDenied", "AccessDeniedException", "InvalidParameterException",
    "ThrottlingException", "TooManyRequestsException", "ConcurrentModificationException",
)


# ===== helpers =====

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


def _cognito_trust_policy(pool_id):
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {"StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id}},
        }],
    })


def _create_role_allowing_prefixes(iam, ctx, pool_id, label, bucket, prefixes):
    """A role Cognito can assume, granting s3:GetObject on exactly the named prefixes."""
    name = ctx.unique_name(f"sim2real-behav-{label}-")[:64]
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_cognito_trust_policy(pool_id),
        Description="sim2real behavioral probe role for Cognito Identity",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy_name = "sim2real-behav-prefix-grant"
    iam.put_role_policy(
        RoleName=name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": [f"arn:aws:s3:::{bucket}/{p}/*" for p in prefixes],
            }],
        }),
    )
    # Registered after delete_role so LIFO cleanup drops the inline policy first.
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName=policy_name))
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
    """A client on the run's target signed with the vended temporary credentials.

    The credentials are handed to ctx.client by value and never written into os.environ, so
    nothing else in this process — and no later subprocess — can pick them up.
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


def _read(client, bucket, key):
    """GetObject; return (body_bytes, None, None) on success or (None, Code, Message) if refused."""
    try:
        return client.get_object(Bucket=bucket, Key=key)["Body"].read(), None, None
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return None, err.get("Code"), err.get("Message") or ""


# ===== check =====

@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An identity used as a guest and then with a developer login keeps the same IdentityId, but
    its guest session is refused the privileged S3 prefix with AccessDenied while its
    authenticated session reads it."""
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-upgrade-")
    s3.create_bucket(
        Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
    )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
    payload_readable = b"sim2real-readable-" + uuid.uuid4().bytes
    payload_privileged = b"sim2real-privileged-" + uuid.uuid4().bytes
    for key, payload in (("readable/obj", payload_readable),
                         ("privileged/obj", payload_privileged)):
        s3.put_object(Bucket=bucket, Key=key, Body=payload)
        ctx.on_cleanup(lambda key=key: s3.delete_object(Bucket=bucket, Key=key))

    developer_provider = ctx.unique_name("sim2real-behav-upgrade-dev-")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_behav_upgrade_").replace("-", "_"),
        AllowUnauthenticatedIdentities=True,
        DeveloperProviderName=developer_provider,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    unauth_role_name, unauth_role_arn = _create_role_allowing_prefixes(
        iam, ctx, pool_id, "upgrade-guest", bucket, ["readable"]
    )
    auth_role_name, auth_role_arn = _create_role_allowing_prefixes(
        iam, ctx, pool_id, "upgrade-member", bucket, ["readable", "privileged"]
    )
    _set_roles(ci, pool_id,
               {"authenticated": auth_role_arn, "unauthenticated": unauth_role_arn})

    # ---- the guest half
    unauth_identity_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[unauth_identity_id]))
    unauth_creds = _poll_until(
        lambda: ci.get_credentials_for_identity(IdentityId=unauth_identity_id),
        lambda r: "Credentials" in r and r["Credentials"].get("SessionToken"),
        timeout_s=120.0,
        description="credentials to be vended for the anonymous identity",
    )["Credentials"]
    s3_guest = _client_from_credentials(ctx, "s3", unauth_creds)
    unauth_role = _poll_until(
        lambda: _client_from_credentials(ctx, "sts", unauth_creds).get_caller_identity(),
        lambda r: bool(r.get("Arn")),
        timeout_s=120.0,
        description="the guest session to become usable by STS",
    )["Arn"]
    assert unauth_role.split("/")[1] == unauth_role_name, (
        f"an identity with no Logins must be vended the unauthenticated role "
        f"{unauth_role_name!r}, got {unauth_role!r}"
    )

    unauth_readable = _poll_until(
        lambda: _read(s3_guest, bucket, "readable/obj"),
        lambda r: r[0] is not None,
        timeout_s=180.0,
        interval_s=5.0,
        description="the guest session to be allowed the prefix its role grants",
    )[0]
    assert unauth_readable == payload_readable, (
        f"the guest read {unauth_readable!r}, expected {payload_readable!r}"
    )

    guest_priv_body, guest_priv_code, guest_priv_msg = _read(
        s3_guest, bucket, "privileged/obj"
    )
    assert guest_priv_code is not None, (
        f"the unauthenticated role grants readable/ only, so the guest session must not read "
        f"privileged/obj, but it returned {guest_priv_body!r}"
    )
    assert guest_priv_code == DENIED_CODE, (
        f"expected {DENIED_CODE!r} for the guest session reading privileged/, got "
        f"{guest_priv_code!r}: {guest_priv_msg!r}"
    )
    assert guest_priv_msg == (
        f"User: {unauth_role} is not authorized to perform: s3:GetObject on resource: "
        f'"arn:aws:s3:::{bucket}/privileged/obj" because no identity-based policy allows the '
        "s3:GetObject action"
    ), f"unexpected AccessDenied message for the guest session: {guest_priv_msg!r}"
    assert guest_priv_body is None, (
        f"a denied GetObject returned a body: {guest_priv_body!r}"
    )

    # ---- change exactly one thing: attach a developer login to that same identity
    developer_user_id = ctx.unique_name("sim2real-behav-upgrade-user-")
    upgraded = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id,
        IdentityId=unauth_identity_id,
        Logins={developer_provider: developer_user_id},
    )
    auth_identity_id = upgraded["IdentityId"]
    assert auth_identity_id == unauth_identity_id, (
        f"the identity id changed on upgrade: {unauth_identity_id!r} -> {auth_identity_id!r}"
    )
    described = ci.describe_identity(IdentityId=auth_identity_id)
    assert developer_provider in described.get("Logins", []), (
        f"identity logins were {described.get('Logins')!r}, expected the developer provider "
        f"{developer_provider!r}"
    )

    auth_creds = _poll_until(
        lambda: ci.get_credentials_for_identity(
            IdentityId=auth_identity_id,
            Logins={DEVELOPER_TOKEN_LOGIN: upgraded["Token"]},
        ),
        lambda r: "Credentials" in r and r["Credentials"].get("SessionToken"),
        timeout_s=120.0,
        description="credentials to be vended for the upgraded identity",
    )["Credentials"]
    auth_role = _poll_until(
        lambda: _client_from_credentials(ctx, "sts", auth_creds).get_caller_identity(),
        lambda r: bool(r.get("Arn")),
        timeout_s=120.0,
        description="the authenticated session to become usable by STS",
    )["Arn"]
    assert auth_role.split("/")[1] == auth_role_name, (
        f"the upgraded identity must be vended the authenticated role {auth_role_name!r}, got "
        f"{auth_role!r}"
    )
    assert unauth_role != auth_role, (
        f"both credential sets assumed {unauth_role!r}, so the authenticated/unauthenticated "
        f"split is not observable"
    )

    # ---- positive control: the same identity now reaches what the guest could not
    s3_member = _client_from_credentials(ctx, "s3", auth_creds)
    auth_priv = _poll_until(
        lambda: _read(s3_member, bucket, "privileged/obj"),
        lambda r: r[0] is not None,
        timeout_s=180.0,
        interval_s=5.0,
        description="the authenticated session to be allowed the privileged prefix",
    )[0]
    assert auth_priv == payload_privileged, (
        f"the authenticated session read {auth_priv!r}, expected {payload_privileged!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
