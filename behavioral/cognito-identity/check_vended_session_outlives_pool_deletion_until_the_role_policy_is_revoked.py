"""vended-session-outlives-pool-deletion-until-the-role-policy-is-revoked."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "vended-session-outlives-pool-deletion-until-the-role-policy-is-revoked"
GROUP = "credentials"
SERVICES = ["cognito-identity"]

_NOT_FOUND = "ResourceNotFoundException"
_DENIED_CODE = "AccessDenied"
_SESSION_NAME = "CognitoIdentityCredentials"
_PROPAGATION_BUDGET_S = 240.0
_REVOKE_BUDGET_S = 240.0
#: How many times the surviving session is re-read after the pool is deleted. A single successful
#: read could be a fluke of ordering; three consecutive identical reads cannot.
_SURVIVAL_READS = 3

_TRANSIENT_SET_ROLES = (
    "AccessDenied", "AccessDeniedException", "InvalidParameterException",
    "ThrottlingException", "TooManyRequestsException", "ConcurrentModificationException",
)


# ===== helpers =====

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
                    "cognito-identity.amazonaws.com:amr": "unauthenticated"
                },
            },
        }],
    })


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
    """Build a client signed with the vended temporary credentials."""
    return ctx.client(service, creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretKey"],
        "aws_session_token": creds["SessionToken"],
    })


def _read(client, bucket, key):
    """GetObject; return (body_bytes, None, None) on success or (None, Code, Message) if refused."""
    try:
        return client.get_object(Bucket=bucket, Key=key)["Body"].read(), None, None
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return None, err.get("Code"), err.get("Message") or ""


def _delete_pool_if_present(ci, pool_id):
    """DeleteIdentityPool for teardown; the body deletes the pool itself, so not-found is done."""
    try:
        ci.delete_identity_pool(IdentityPoolId=pool_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != _NOT_FOUND:
            raise


def _delete_role_policy_if_present(iam, role_name, policy_name):
    """DeleteRolePolicy for teardown; the body deletes the policy itself, so NoSuchEntity is done."""
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _refusal(fn, what):
    """Call fn() expecting a refusal; return (Code, Message). RAISES on unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"{what} must have been refused, but it returned {result!r}")


# ===== check =====

@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """After DeleteIdentityPool the pool resolves nothing and vends nothing new, while credentials
    it already vended keep reading the object their role allows until the role's grant is
    removed, at which point the same live session is refused."""
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-survive-")
    s3.create_bucket(
        Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
    )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
    key = "survivor/obj"
    payload = b"sim2real-survivor-" + uuid.uuid4().bytes
    s3.put_object(Bucket=bucket, Key=key, Body=payload)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_behav_survive_").replace("-", "_"),
        AllowUnauthenticatedIdentities=True,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: _delete_pool_if_present(ci, pool_id))

    role_name = ctx.unique_name("sim2real-behav-survive-role-")[:64]
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_cognito_trust_policy(pool_id),
        Description="sim2real behavioral probe role for Cognito Identity",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "sim2real-behav-survive-grant"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/{key}",
            }],
        }),
    )
    # Registered after delete_role so LIFO teardown drops the inline policy first; the body deletes
    # it too, so teardown treats an already-deleted policy as done.
    ctx.on_cleanup(lambda: _delete_role_policy_if_present(iam, role_name, policy_name))
    _set_roles(ci, pool_id, {"unauthenticated": role_arn})

    identity_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    creds = _poll_until(
        lambda: ci.get_credentials_for_identity(IdentityId=identity_id),
        lambda r: "Credentials" in r and r["Credentials"].get("SessionToken"),
        timeout_s=_PROPAGATION_BUDGET_S,
        description="the guest identity to be vended credentials",
    )["Credentials"]
    session = _client_from_credentials(ctx, "s3", creds)

    # ---- positive control: the live session reads the exact bytes its role grants.
    control_body = _poll_until(
        lambda: _read(session, bucket, key),
        lambda r: r[0] is not None,
        timeout_s=_PROPAGATION_BUDGET_S,
        description="the vended session to be allowed the object its role grants",
    )[0]
    assert control_body == payload, (
        f"control: the vended session read {control_body!r}, expected {payload!r}"
    )

    # ---- the pool goes away.
    ci.delete_identity_pool(IdentityPoolId=pool_id)

    # The delete is real, proved by two independent reads through operations that are not the
    # delete: no new credentials, and the identity no longer resolves.
    vend_code, vend_message = _refusal(
        lambda: ci.get_credentials_for_identity(IdentityId=identity_id),
        "GetCredentialsForIdentity against a deleted pool",
    )
    assert vend_code == _NOT_FOUND, (
        f"expected {_NOT_FOUND} from GetCredentialsForIdentity after the pool was deleted, got "
        f"{vend_code!r}: {vend_message!r}"
    )
    expected = f"IdentityPool '{pool_id}' not found."
    assert vend_message == expected, (
        f"expected the message {expected!r} from GetCredentialsForIdentity after the pool was "
        f"deleted, got {vend_message!r}"
    )
    describe_code, describe_message = _refusal(
        lambda: ci.describe_identity(IdentityId=identity_id),
        "DescribeIdentity against a deleted pool",
    )
    assert describe_code == _NOT_FOUND, (
        f"expected {_NOT_FOUND} from DescribeIdentity after the pool was deleted, got "
        f"{describe_code!r}: {describe_message!r}"
    )
    expected = f"IdentityPool '{pool_id}' not found."
    assert describe_message == expected, (
        f"expected the message {expected!r} from DescribeIdentity after the pool was deleted, got "
        f"{describe_message!r}"
    )

    # ---- and yet the session already in flight is untouched, read repeatedly so one fluke cannot
    # decide it. Each read returns the exact bytes, not merely a 200.
    for attempt in range(_SURVIVAL_READS):
        body, code, message = _read(session, bucket, key)
        assert code is None, (
            f"read {attempt + 1} of {_SURVIVAL_READS}: deleting the identity pool must not revoke "
            f"an already-vended STS session, but S3 refused it with {code!r}: {message!r}"
        )
        assert body == payload, (
            f"read {attempt + 1} of {_SURVIVAL_READS}: the surviving session read {body!r}, "
            f"expected {payload!r}"
        )

    # ---- the demonstrated control: the session CAN be stopped, so "it still worked" above was a
    # measurement and not the absence of any enforcement at all. Remove the role's only Allow.
    iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    revoked = _poll_until(
        lambda: _read(session, bucket, key),
        lambda r: r[1] is not None,
        timeout_s=_REVOKE_BUDGET_S,
        description="the live session to be denied once the role's only Allow is removed",
    )
    assert revoked[1] == _DENIED_CODE, (
        f"expected {_DENIED_CODE!r} once the role grant was removed, got {revoked[1]!r}: "
        f"{revoked[2]!r}"
    )
    assert revoked[0] is None, (
        f"a denied GetObject returned a body: {revoked[0]!r}"
    )
    partition, account = role_arn.split(":")[1], role_arn.split(":")[4]
    session_arn = f"arn:{partition}:sts::{account}:assumed-role/{role_name}/{_SESSION_NAME}"
    expected = (
        f"User: {session_arn} is not authorized to perform: s3:GetObject on resource: "
        f'"arn:{partition}:s3:::{bucket}/{key}" because no identity-based policy allows the '
        f"s3:GetObject action"
    )
    assert revoked[2] == expected, (
        f"expected the denial message {expected!r} once the role grant was removed, got "
        f"{revoked[2]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
