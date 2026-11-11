"""swapping-the-authenticated-role-moves-the-next-session-and-spares-the-live-one."""
from __future__ import annotations

import json
import time
import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "swapping-the-authenticated-role-moves-the-next-session-and-spares-the-live-one"
GROUP = 'role-mapping'
SERVICES = ['cognito-identity']

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


def _create_role_allowing_prefix(iam, ctx, pool_id, label, bucket, prefix):
    """A role Cognito can assume, granting s3:GetObject on exactly one prefix."""
    name = ctx.unique_name(f"sim2real-behav-{label}-")[:64]
    arn = iam.create_role(
        RoleName=name,
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
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy_name = "sim2real-behav-swap-grant"
    iam.put_role_policy(
        RoleName=name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/{prefix}/*",
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


def _read(client, bucket, key):
    """GetObject; return (body_bytes, None, None) on success or (None, Code, Message) if refused."""
    try:
        return client.get_object(Bucket=bucket, Key=key)["Body"].read(), None, None
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return None, err.get("Code"), err.get("Message") or ""


# ===== check =====

@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:e2e",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """After SetIdentityPoolRoles swaps the authenticated role, the next GetCredentialsForIdentity
    vends the new role and reaches its S3 prefix instead of the old one, while the session vended
    before the swap keeps working on the prefix it was granted."""
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-roleswap-")
    s3.create_bucket(
        Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
    )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
    payload_old = b"sim2real-old-" + uuid.uuid4().bytes
    payload_new = b"sim2real-new-" + uuid.uuid4().bytes
    for key, payload in (("old/obj", payload_old), ("new/obj", payload_new)):
        s3.put_object(Bucket=bucket, Key=key, Body=payload)
        ctx.on_cleanup(lambda key=key: s3.delete_object(Bucket=bucket, Key=key))

    developer_provider = ctx.unique_name("sim2real-behav-roleswap-dev-")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_behav_roleswap_").replace("-", "_"),
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=developer_provider,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    role_old_name, role_old_arn = _create_role_allowing_prefix(
        iam, ctx, pool_id, "roleswap-old", bucket, "old"
    )
    role_new_name, role_new_arn = _create_role_allowing_prefix(
        iam, ctx, pool_id, "roleswap-new", bucket, "new"
    )
    _set_roles(ci, pool_id, {"authenticated": role_old_arn})

    developer_user_id = ctx.unique_name("sim2real-behav-roleswap-user-")

    def _vend():
        token = ci.get_open_id_token_for_developer_identity(
            IdentityPoolId=pool_id, Logins={developer_provider: developer_user_id}
        )
        vended = _poll_until(
            lambda: ci.get_credentials_for_identity(
                IdentityId=token["IdentityId"],
                Logins={DEVELOPER_TOKEN_LOGIN: token["Token"]},
            ),
            lambda r: "Credentials" in r and r["Credentials"].get("SessionToken"),
            timeout_s=120.0,
            description="GetCredentialsForIdentity to vend a session",
        )
        return token["IdentityId"], vended["Credentials"]

    identity_id, old_creds = _vend()
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_id]))
    s3_old = _client_from_credentials(ctx, "s3", old_creds)
    old_arn = _poll_until(
        lambda: _client_from_credentials(ctx, "sts", old_creds).get_caller_identity(),
        lambda r: bool(r.get("Arn")),
        timeout_s=120.0,
        description="the pre-swap session to become usable by STS",
    )["Arn"]
    assert old_arn.split("/")[1] == role_old_name, (
        f"the pre-swap session assumed {old_arn!r}, expected the configured role "
        f"{role_old_name!r}"
    )

    old_body = _poll_until(
        lambda: _read(s3_old, bucket, "old/obj"),
        lambda r: r[0] is not None,
        timeout_s=180.0,
        interval_s=5.0,
        description="the pre-swap session to be allowed the prefix its role grants",
    )[0]
    assert old_body == payload_old, (
        f"the pre-swap session read {old_body!r}, expected {payload_old!r}"
    )
    _, old_new_code, old_new_msg = _read(s3_old, bucket, "new/obj")
    assert old_new_code == DENIED_CODE, (
        f"the pre-swap role grants old/ only, so new/obj must be refused with {DENIED_CODE!r}, "
        f"got {old_new_code!r}: {old_new_msg!r}"
    )

    # ---- change exactly one thing: the pool's authenticated role
    _set_roles(ci, pool_id, {"authenticated": role_new_arn})
    stored = ci.get_identity_pool_roles(IdentityPoolId=pool_id)["Roles"]
    assert stored["authenticated"] == role_new_arn, (
        f"GetIdentityPoolRoles reports {stored['authenticated']!r} after the swap, expected "
        f"{role_new_arn!r}"
    )

    # ---- the already-issued session is a snapshot the swap does not reach
    old_body_after, old_after_code, old_after_msg = _read(s3_old, bucket, "old/obj")
    assert old_body_after == payload_old, (
        f"the pre-swap session stopped working after the role swap: {old_body_after!r} "
        f"(code {old_after_code!r}: {old_after_msg!r})"
    )

    # ---- the next vend for the SAME identity moves to the new role
    fresh_arn_holder = {}

    def _fresh_session():
        _, fresh = _vend()
        client = _client_from_credentials(ctx, "sts", fresh)
        arn = client.get_caller_identity()["Arn"]
        fresh_arn_holder["creds"] = fresh
        fresh_arn_holder["arn"] = arn
        return arn

    fresh_arn = _poll_until(
        _fresh_session,
        lambda arn: arn.split("/")[1] == role_new_name,
        timeout_s=180.0,
        interval_s=5.0,
        description="a freshly vended session to resolve to the newly configured role",
    )
    assert fresh_arn.split("/")[1] == role_new_name, (
        f"a session vended after the swap assumed {fresh_arn!r}, expected the new role "
        f"{role_new_name!r}"
    )
    assert fresh_arn != old_arn, (
        f"the pre-swap and post-swap sessions are the same principal {fresh_arn!r}, so the swap "
        f"is not observable"
    )

    s3_fresh = _client_from_credentials(ctx, "s3", fresh_arn_holder["creds"])
    fresh_new = _poll_until(
        lambda: _read(s3_fresh, bucket, "new/obj"),
        lambda r: r[0] is not None,
        timeout_s=180.0,
        interval_s=5.0,
        description="the post-swap session to be allowed the new role's prefix",
    )[0]
    assert fresh_new == payload_new, (
        f"the post-swap session read {fresh_new!r}, expected {payload_new!r}"
    )
    _, fresh_old_code, fresh_old_msg = _read(s3_fresh, bucket, "old/obj")
    assert fresh_old_code == DENIED_CODE, (
        f"the post-swap session must no longer reach old/, expected {DENIED_CODE!r}, got "
        f"{fresh_old_code!r}: {fresh_old_msg!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
