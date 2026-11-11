"""xsvc-cognito-identity-1-encryption-context-scoped-key-grant-denied-vended-session-outside-its-prefix."""
from __future__ import annotations

import json
import time
import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cognito-identity-1-encryption-context-scoped-key-grant-denied-vended-session-outside-its-prefix"
GROUP = "encryption-rejection"
SERVICES = ["cognito-identity", "kms", "s3"]

COGNITO_PROVIDER = "cognito-identity.amazonaws.com"
_POLICY_NAME = "sim2real-xsvc-get-object-only"
_GRANT_SID = "sim2realXsvcDecryptForVendedRoleUnderOpenPrefix"
_OPEN_KEY = "open/payload.txt"
_CLOSED_KEY = "closed/payload.txt"
_OPEN_BODY = b"sim2real xsvc sse-kms open-prefix payload\n"
_CLOSED_BODY = b"sim2real xsvc sse-kms closed-prefix payload\n"


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
    """A client on the target signed with Cognito-vended credentials, never via os.environ."""
    return ctx.client(
        service,
        config=Config(retries={"max_attempts": 2}),
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _refusal(fn, why):
    """Call fn() expecting a refusal; return its (Code, Message). A success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"{why}: the call SUCCEEDED and returned {result!r}")


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

@tags("axis:rejection", "dp:api", "plane:data", "cap:c1", "concern:e2e")
def run(ctx) -> None:
    """A kms:Decrypt grant to the authenticated role, conditioned on S3's encryption context naming
    the open/ prefix, lets a vended session read SSE-KMS objects there but not one prefix over
    (AccessDenied naming kms:Decrypt); widening the condition to that prefix admits the read.
    """
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
    # No bucket key: with one the encryption context is the bucket ARN, matching neither prefix.
    for key, data in ((_OPEN_KEY, _OPEN_BODY), (_CLOSED_KEY, _CLOSED_BODY)):
        put = s3.put_object(Bucket=bucket, Key=key, Body=data, ServerSideEncryption="aws:kms",
                            SSEKMSKeyId=key_arn, BucketKeyEnabled=False)
        assert put["SSEKMSKeyId"] == key_arn and not put.get("BucketKeyEnabled"), (
            f"{key} must be SSE-KMS under {key_arn} without a bucket key, got "
            f"{put.get('SSEKMSKeyId')!r} / BucketKeyEnabled={put.get('BucketKeyEnabled')!r}"
        )

    developer_provider = "sim2real-xsvc-dev-" + uuid.uuid4().hex[:8]
    pool_name = ctx.unique_name("sim2real_xsvc_cogkms_").replace("-", "_")
    pool_id = ci.create_identity_pool(
        IdentityPoolName=pool_name,
        AllowUnauthenticatedIdentities=False,
        DeveloperProviderName=developer_provider,
        IdentityPoolTags={"sim2real": "xsvc-cognito-identity-1"},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": COGNITO_PROVIDER},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {f"{COGNITO_PROVIDER}:aud": pool_id},
                "ForAnyValue:StringLike": {f"{COGNITO_PROVIDER}:amr": "authenticated"},
            },
        }],
    }
    role_name = ctx.unique_name("sim2real-xsvc-cogkms-auth-")[:64]
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "xsvc-cognito-identity-1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName=_POLICY_NAME, PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                       "Resource": f"arn:aws:s3:::{bucket}/*"}],
    }))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=_POLICY_NAME))
    _set_roles(ci, pool_id, {"authenticated": role_arn})

    def _with_condition(prefixes):
        policy = json.loads(json.dumps(original_policy))
        policy["Statement"].append({
            "Sid": _GRANT_SID,
            "Effect": "Allow",
            "Principal": {"AWS": role_arn},
            "Action": "kms:Decrypt",
            "Resource": "*",
            "Condition": {"StringLike": {"kms:EncryptionContext:aws:s3:arn": [
                f"arn:aws:s3:::{bucket}/{p}*" for p in prefixes]}},
        })
        return policy

    _put_key_policy(kms, key_id, _with_condition(["open/"]))

    user = "sim2real-xsvc-user-" + uuid.uuid4().hex[:12]
    minted = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={developer_provider: user}, TokenDuration=900,
    )
    identity_id, token = minted["IdentityId"], minted["Token"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_id]))

    def _vended_s3():
        return _session_client(ctx, "s3", ci.get_credentials_for_identity(
            IdentityId=identity_id, Logins={COGNITO_PROVIDER: token})["Credentials"])

    # ---- positive control and propagation barrier: the open-prefix read succeeds
    got = _poll_until(
        lambda: _vended_s3().get_object(Bucket=bucket, Key=_OPEN_KEY),
        lambda r: r.get("ServerSideEncryption") == "aws:kms",
        timeout_s=180.0, interval_s=10.0,
        description="the context-conditioned grant to admit the open-prefix SSE-KMS read",
    )
    assert got["Body"].read() == _OPEN_BODY, "the open-prefix read returned different bytes"

    # ---- the refusal: same session, same CMK, the other prefix
    vs3 = _vended_s3()
    code, msg = _refusal(
        lambda: vs3.get_object(Bucket=bucket, Key=_CLOSED_KEY)["Body"].read(),
        "the key policy's encryption-context condition names open/* only, yet the vended session "
        "read an object under closed/",
    )
    assert code == "AccessDenied", f"expected AccessDenied for closed/, got {code!r}: {msg!r}"
    # The refusal is KMS's decrypt on this key for the vended session, not an S3 denial.
    session_arn = f"arn:aws:sts::{ctx.account}:assumed-role/{role_name}/CognitoIdentityCredentials"
    expected = (
        f"User: {session_arn} is not authorized to perform: kms:Decrypt on resource: {key_arn} "
        "because no identity-based policy allows the kms:Decrypt action"
    )
    assert msg == expected, f"closed/ refusal: expected {expected!r}, got {msg!r}"
    assert vs3.get_object(Bucket=bucket, Key=_OPEN_KEY)["Body"].read() == _OPEN_BODY, (
        "the same session must still read open/ right after closed/ was refused"
    )
    head = vs3.head_object(Bucket=bucket, Key=_CLOSED_KEY)
    assert head["SSEKMSKeyId"] == key_arn and head["ContentLength"] == len(_CLOSED_BODY), (
        f"HeadObject must still see the intact closed/ object, got {head.get('SSEKMSKeyId')!r} / "
        f"{head.get('ContentLength')!r}"
    )

    # ---- repair exactly one thing: widen the condition to closed/ as well
    _put_key_policy(kms, key_id, _with_condition(["open/", "closed/"]))
    closed = _poll_until(
        lambda: _vended_s3().get_object(Bucket=bucket, Key=_CLOSED_KEY),
        lambda r: r.get("ServerSideEncryption") == "aws:kms",
        timeout_s=180.0, interval_s=10.0,
        description="the widened encryption-context condition to admit the closed/ read",
    )
    assert closed["Body"].read() == _CLOSED_BODY, "the closed/ read returned different bytes"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
