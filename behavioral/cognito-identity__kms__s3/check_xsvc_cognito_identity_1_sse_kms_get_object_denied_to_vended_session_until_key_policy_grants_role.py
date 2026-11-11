"""xsvc-cognito-identity-1-sse-kms-get-object-denied-to-vended-session-until-key-policy-grants-role."""
from __future__ import annotations

import json
import time
import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cognito-identity-1-sse-kms-get-object-denied-to-vended-session-until-key-policy-grants-role"
GROUP = "encryption-rejection"
SERVICES = ["cognito-identity", "kms", "s3"]
#: The RoleSessionName cognito-identity gives every session it vends.
COGNITO_SESSION_NAME = "CognitoIdentityCredentials"

COGNITO_PROVIDER = "cognito-identity.amazonaws.com"
_POLICY_NAME = "sim2real-xsvc-get-object-only"
_GRANT_SID = "sim2realXsvcDecryptForVendedRole"
_KMS_KEY = "kms/payload.txt"
_SSE_S3_KEY = "sse-s3/payload.txt"
_KMS_BODY = b"sim2real xsvc sse-kms payload\n"
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


@tags("axis:rejection", "dp:api", "plane:data", "cap:c1", "concern:e2e")
def run(ctx) -> None:
    """A vended session whose role allows only s3:GetObject reads the SSE-S3 object, is refused the
    SSE-KMS one with 403 AccessDenied and the exact kms:Decrypt message, and still heads it;
    granting kms:Decrypt to the role in the key policy makes the read return the exact bytes."""
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    kms = ctx.client("kms")
    s3 = ctx.client("s3")

    # ---- the CMK: default key policy, nothing granted to the role
    created = kms.create_key(
        Description=ctx.unique_name("sim2real-xsvc-cognito-kms-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "xsvc-cognito-identity-1"}],
    )["KeyMetadata"]
    key_id, key_arn = created["KeyId"], created["Arn"]
    ctx.on_cleanup(lambda: _retire_key(kms, key_id))
    original_policy = json.loads(kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"])

    # ---- the bucket and its two objects, written by the account (not by the vended session)
    bucket = ctx.unique_name("sim2real-xsvc-cogkms-").lower()[:63]
    params = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={
        "TagSet": [{"Key": "sim2real", "Value": "xsvc-cognito-identity-1"}]})
    put_kms = s3.put_object(Bucket=bucket, Key=_KMS_KEY, Body=_KMS_BODY,
                            ServerSideEncryption="aws:kms", SSEKMSKeyId=key_arn,
                            BucketKeyEnabled=False)
    assert put_kms["ServerSideEncryption"] == "aws:kms" and put_kms["SSEKMSKeyId"] == key_arn, (
        f"the SSE-KMS write must report aws:kms under {key_arn}, got "
        f"{put_kms.get('ServerSideEncryption')!r} / {put_kms.get('SSEKMSKeyId')!r}"
    )
    put_s3 = s3.put_object(Bucket=bucket, Key=_SSE_S3_KEY, Body=_SSE_S3_BODY,
                           ServerSideEncryption="AES256")
    assert put_s3["ServerSideEncryption"] == "AES256", (
        f"the control write must be SSE-S3 (AES256), got {put_s3.get('ServerSideEncryption')!r}"
    )

    # ---- the identity pool and its authenticated role: s3:GetObject on this bucket, nothing else
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

    user = "sim2real-xsvc-user-" + uuid.uuid4().hex[:12]
    minted = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={developer_provider: user}, TokenDuration=900,
    )
    identity_id, token = minted["IdentityId"], minted["Token"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_id]))

    def _vended_s3():
        creds = ci.get_credentials_for_identity(
            IdentityId=identity_id, Logins={COGNITO_PROVIDER: token})["Credentials"]
        return _session_client(ctx, "s3", creds)

    # ---- control: the SSE-S3 object is readable (this also waits out IAM propagation)
    control = _poll_until(
        lambda: _vended_s3().get_object(Bucket=bucket, Key=_SSE_S3_KEY),
        lambda r: r.get("ServerSideEncryption") == "AES256",
        timeout_s=180.0, interval_s=10.0,
        description="the role's s3:GetObject grant to admit a vended session on the SSE-S3 object",
    )
    assert control["Body"].read() == _SSE_S3_BODY, "the SSE-S3 control object's bytes changed"

    # ---- the refusal: same session, same grant, the SSE-KMS object
    vs3 = _vended_s3()
    err = _client_error(lambda: vs3.get_object(Bucket=bucket, Key=_KMS_KEY)["Body"].read())
    assert err is not None, (
        "a vended session with no path to kms:Decrypt must not read an SSE-KMS object, but "
        "GetObject returned its body"
    )
    code = err.response.get("Error", {}).get("Code")
    msg = err.response.get("Error", {}).get("Message") or ""
    assert code == "AccessDenied", f"expected AccessDenied on the SSE-KMS read, got {code!r}: {msg!r}"
    assert err.response["ResponseMetadata"]["HTTPStatusCode"] == 403, (
        f"an S3 AccessDenied is a 403, got {err.response['ResponseMetadata']['HTTPStatusCode']!r}"
    )
    account = key_arn.split(":")[4]
    expected = (
        f"User: arn:aws:sts::{account}:assumed-role/{role_name}/{COGNITO_SESSION_NAME} is not "
        f"authorized to perform: kms:Decrypt on resource: {key_arn} because no identity-based "
        "policy allows the kms:Decrypt action"
    )
    assert msg == expected, (
        f"the refusal must be the KMS decrypt on this key by the vended session, exactly "
        f"{expected!r}; got {msg!r}"
    )
    # Same session, immediately: the SSE-S3 control still reads — the denial is KMS-specific.
    assert vs3.get_object(Bucket=bucket, Key=_SSE_S3_KEY)["Body"].read() == _SSE_S3_BODY, (
        "the SSE-S3 object must stay readable to the session the SSE-KMS read was refused to"
    )
    # Effect absent at the object, not destroyed: HeadObject needs no decrypt and still sees it.
    head = vs3.head_object(Bucket=bucket, Key=_KMS_KEY)
    assert head["ServerSideEncryption"] == "aws:kms" and head["SSEKMSKeyId"] == key_arn, (
        f"HeadObject must still report the object as aws:kms under {key_arn}, got "
        f"{head.get('ServerSideEncryption')!r} / {head.get('SSEKMSKeyId')!r}"
    )
    assert head["ContentLength"] == len(_KMS_BODY), (
        f"HeadObject must report the stored length {len(_KMS_BODY)}, got {head['ContentLength']!r}"
    )

    # ---- repair exactly one thing: a key-policy statement granting kms:Decrypt to the role
    granted_policy = json.loads(json.dumps(original_policy))
    granted_policy["Statement"].append({
        "Sid": _GRANT_SID,
        "Effect": "Allow",
        "Principal": {"AWS": role_arn},
        "Action": "kms:Decrypt",
        "Resource": "*",
    })
    _put_key_policy(kms, key_id, granted_policy)
    live = json.loads(kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"])
    assert any(s.get("Sid") == _GRANT_SID for s in live["Statement"]), (
        f"GetKeyPolicy must return the statement just put, got Sids "
        f"{[s.get('Sid') for s in live['Statement']]!r}"
    )

    got = _poll_until(
        lambda: _vended_s3().get_object(Bucket=bucket, Key=_KMS_KEY),
        lambda r: r.get("ServerSideEncryption") == "aws:kms",
        timeout_s=180.0, interval_s=10.0,
        description="the key-policy grant to admit a vended session's SSE-KMS read",
    )
    assert got["SSEKMSKeyId"] == key_arn, (
        f"the decrypted read must report the CMK {key_arn}, got {got.get('SSEKMSKeyId')!r}"
    )
    assert got["Body"].read() == _KMS_BODY, "the SSE-KMS object's bytes changed across the grant"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
