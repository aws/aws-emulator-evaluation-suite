"""xsvc-cognito-identity-1-guest-session-denied-sse-kms-read-key-policy-grants-authenticated-only."""
from __future__ import annotations

import json
import time
import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cognito-identity-1-guest-session-denied-sse-kms-read-key-policy-grants-authenticated-only"
GROUP = "encryption-rejection"
SERVICES = ["cognito-identity", "kms", "s3"]

COGNITO_PROVIDER = "cognito-identity.amazonaws.com"
COGNITO_SESSION_NAME = "CognitoIdentityCredentials"
_POLICY_NAME = "sim2real-xsvc-get-object-only"
_AUTH_SID = "sim2realXsvcDecryptForAuthenticatedRole"
_GUEST_SID = "sim2realXsvcDecryptForGuestRole"
_KMS_KEY = "kms/payload.txt"
_SSE_S3_KEY = "sse-s3/payload.txt"
_KMS_BODY = b"sim2real xsvc sse-kms role-scoped payload\n"
_SSE_S3_BODY = b"sim2real xsvc sse-s3 control payload\n"


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


_TRANSIENT_SET_ROLES = (
    "AccessDenied", "AccessDeniedException", "InvalidParameterException",
    "ThrottlingException", "TooManyRequestsException", "ConcurrentModificationException",
)


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


def _session_client(ctx, service, creds):
    """A client signed with Cognito-vended credentials, passed explicitly — never via os.environ."""
    return ctx.client(
        service,
        config=Config(retries={"max_attempts": 2}),
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _client_error(fn):
    """Call fn(); return the ClientError it raised, or None if it returned normally. Returning the
    exception (never a falsy code) keeps "the target accepted it" distinguishable from a code."""
    try:
        fn()
    except ClientError as exc:
        return exc
    return None


def _delete_bucket(s3, bucket):
    """Empty and delete a bucket this check created; scoped so it never reaches another run."""
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchBucket":
            raise


def _retire_key(kms, key_id):
    """Schedule the CMK for deletion at AWS's 7-day floor — it cannot be deleted synchronously."""
    for attempt in range(4):
        try:
            kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "KMSInvalidStateException":
                return
            if code != "ThrottlingException" or attempt == 3:
                raise
            time.sleep(2 * (attempt + 1))


def _put_key_policy(kms, key_id, policy, timeout_s=120.0):
    """PutKeyPolicy, retrying only the rejection KMS gives while a new role principal propagates."""
    deadline = time.time() + timeout_s
    while True:
        try:
            return kms.put_key_policy(KeyId=key_id, PolicyName="default",
                                      Policy=json.dumps(policy))
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "MalformedPolicyDocumentException" or time.time() >= deadline:
                raise
            time.sleep(5.0)


def _role(iam, ctx, label, pool_id, amr, bucket):
    """A Cognito-trusting role for one amr class, allowed s3:GetObject on this bucket only."""
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": COGNITO_PROVIDER},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {f"{COGNITO_PROVIDER}:aud": pool_id},
                "ForAnyValue:StringLike": {f"{COGNITO_PROVIDER}:amr": amr},
            },
        }],
    }
    name = ctx.unique_name(f"sim2real-xsvc-cogkms-{label}-")[:64]
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "xsvc-cognito-identity-1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(RoleName=name, PolicyName=_POLICY_NAME, PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                       "Resource": f"arn:aws:s3:::{bucket}/*"}],
    }))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName=_POLICY_NAME))
    return name, arn


def _decrypt_grant(sid, role_arn):
    return {"Sid": sid, "Effect": "Allow", "Principal": {"AWS": role_arn},
            "Action": "kms:Decrypt", "Resource": "*"}


@tags("axis:rejection", "dp:api", "plane:data", "cap:c1", "concern:e2e")
def run(ctx) -> None:
    """With kms:Decrypt granted to the authenticated role only, the authenticated session reads the
    SSE-KMS object and the guest session gets AccessDenied with the exact kms:Decrypt message, both
    reading the SSE-S3 object; granting the guest role lets it read."""
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    kms = ctx.client("kms")
    s3 = ctx.client("s3")

    created = kms.create_key(
        Description=ctx.unique_name("sim2real-xsvc-cognito-kms-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "xsvc-cognito-identity-1"}],
    )["KeyMetadata"]
    key_id, key_arn = created["KeyId"], created["Arn"]
    ctx.on_cleanup(lambda: _retire_key(kms, key_id))
    original_policy = json.loads(kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"])

    bucket = ctx.unique_name("sim2real-xsvc-cogkms-").lower()[:63]
    params = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={
        "TagSet": [{"Key": "sim2real", "Value": "xsvc-cognito-identity-1"}]})
    s3.put_object(Bucket=bucket, Key=_KMS_KEY, Body=_KMS_BODY, ServerSideEncryption="aws:kms",
                  SSEKMSKeyId=key_arn, BucketKeyEnabled=False)
    s3.put_object(Bucket=bucket, Key=_SSE_S3_KEY, Body=_SSE_S3_BODY,
                  ServerSideEncryption="AES256")

    developer_provider = "sim2real-xsvc-dev-" + uuid.uuid4().hex[:8]
    pool_name = ctx.unique_name("sim2real_xsvc_cogkms_").replace("-", "_")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=True,
        DeveloperProviderName=developer_provider,
        IdentityPoolTags={"sim2real": "xsvc-cognito-identity-1"},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    _, auth_arn = _role(iam, ctx, "auth", pool_id, "authenticated", bucket)
    guest_name, guest_arn = _role(iam, ctx, "guest", pool_id, "unauthenticated", bucket)
    _set_roles(ci, pool_id, {"authenticated": auth_arn, "unauthenticated": guest_arn})

    # Key policy: default + Decrypt for the AUTHENTICATED role only.
    scoped = json.loads(json.dumps(original_policy))
    scoped["Statement"].append(_decrypt_grant(_AUTH_SID, auth_arn))
    _put_key_policy(kms, key_id, scoped)

    user = "sim2real-xsvc-user-" + uuid.uuid4().hex[:12]
    minted = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={developer_provider: user}, TokenDuration=900,
    )
    auth_id, token = minted["IdentityId"], minted["Token"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[auth_id]))
    guest_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[guest_id]))
    assert guest_id != auth_id, "the guest and the developer identity must be distinct identities"

    def _auth_s3():
        return _session_client(ctx, "s3", ci.get_credentials_for_identity(
            IdentityId=auth_id, Logins={COGNITO_PROVIDER: token})["Credentials"])

    def _guest_s3():
        return _session_client(ctx, "s3", ci.get_credentials_for_identity(
            IdentityId=guest_id)["Credentials"])

    # ---- positive control: the authenticated session reads the SSE-KMS bytes
    got = _poll_until(
        lambda: _auth_s3().get_object(Bucket=bucket, Key=_KMS_KEY),
        lambda r: r.get("ServerSideEncryption") == "aws:kms",
        timeout_s=180.0, interval_s=10.0,
        description="the authenticated session's SSE-KMS read under the role-scoped key policy",
    )
    assert got["SSEKMSKeyId"] == key_arn, f"expected CMK {key_arn}, got {got.get('SSEKMSKeyId')!r}"
    assert got["Body"].read() == _KMS_BODY, "the authenticated read returned different bytes"

    # The guest's S3 grant is live (this also waits out IAM propagation for the guest role).
    control = _poll_until(
        lambda: _guest_s3().get_object(Bucket=bucket, Key=_SSE_S3_KEY),
        lambda r: r.get("ServerSideEncryption") == "AES256",
        timeout_s=180.0, interval_s=10.0,
        description="the guest role's s3:GetObject grant to admit a guest session",
    )
    assert control["Body"].read() == _SSE_S3_BODY, "the SSE-S3 control object's bytes changed"

    # ---- the refusal: the guest session on the SSE-KMS object
    gs3 = _guest_s3()
    err = _client_error(lambda: gs3.get_object(Bucket=bucket, Key=_KMS_KEY)["Body"].read())
    assert err is not None, (
        "the key policy grants kms:Decrypt to the authenticated role only, yet a guest session "
        "read the SSE-KMS object"
    )
    code = err.response.get("Error", {}).get("Code")
    msg = err.response.get("Error", {}).get("Message") or ""
    assert code == "AccessDenied", f"expected AccessDenied for the guest read, got {code!r}: {msg!r}"
    account = key_arn.split(":")[4]
    expected = (
        f"User: arn:aws:sts::{account}:assumed-role/{guest_name}/{COGNITO_SESSION_NAME} is not "
        f"authorized to perform: kms:Decrypt on resource: {key_arn} because no identity-based "
        "policy allows the kms:Decrypt action"
    )
    assert msg == expected, (
        f"the guest refusal must be the KMS decrypt on this key by the guest role's vended "
        f"session, exactly {expected!r}; got {msg!r}"
    )
    head = gs3.head_object(Bucket=bucket, Key=_KMS_KEY)
    assert head["SSEKMSKeyId"] == key_arn and head["ContentLength"] == len(_KMS_BODY), (
        f"HeadObject must still see the intact SSE-KMS object, got {head.get('SSEKMSKeyId')!r} / "
        f"{head.get('ContentLength')!r}"
    )
    assert gs3.get_object(Bucket=bucket, Key=_SSE_S3_KEY)["Body"].read() == _SSE_S3_BODY, (
        "the same guest session must still read the SSE-S3 object — the refusal is KMS-specific"
    )

    # ---- repair exactly one thing: add the guest role to the key policy
    widened = json.loads(json.dumps(scoped))
    widened["Statement"].append(_decrypt_grant(_GUEST_SID, guest_arn))
    _put_key_policy(kms, key_id, widened)
    guest_got = _poll_until(
        lambda: _guest_s3().get_object(Bucket=bucket, Key=_KMS_KEY),
        lambda r: r.get("ServerSideEncryption") == "aws:kms",
        timeout_s=180.0, interval_s=10.0,
        description="the widened key policy to admit the guest session's SSE-KMS read",
    )
    assert guest_got["Body"].read() == _KMS_BODY, "the guest's post-grant read returned other bytes"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
