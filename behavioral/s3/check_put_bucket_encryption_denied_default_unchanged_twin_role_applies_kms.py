"""put-bucket-encryption-denied-default-unchanged-twin-role-applies-kms."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-bucket-encryption-denied-default-unchanged-twin-role-applies-kms"
GROUP = "auth_enforcement"
SERVICES = ["s3", "iam", "sts"]

_KMS_CONFIG = {
    "Rules": [{
        "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"},
        "BucketKeyEnabled": True,
    }]
}


def _delete_bucket(s3, bucket: str) -> None:
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3) -> str:
    name = ctx.unique_name("sim2real-putenc-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _remove_role(iam, role_name: str, policy_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _role_with_actions(ctx, iam, name_prefix: str, actions: list[str], bucket_arn: str) -> tuple[str, str]:
    """A role this account's root can assume, holding exactly `actions` on `bucket_arn`.
    Returns (role_arn, role_name); teardown is registered."""
    role_name = ctx.unique_name(name_prefix)
    policy_name = f"{role_name}-perms"
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
            "Action": "sts:AssumeRole",
        }],
    })
    created = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)
    ctx.on_cleanup(lambda: _remove_role(iam, role_name, policy_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": actions, "Resource": bucket_arn}],
        }),
    )
    return created["Role"]["Arn"], role_name


def _assumed_creds(ctx, role_arn: str, session_name: str, attempts: int = 15, delay_s: float = 3.0):
    """Temp credential kwargs for `role_arn`; retries while the role's trust propagates."""
    sts = ctx.client("sts")
    last_exc: ClientError | None = None
    for _ in range(attempts):
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
            return {
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds["SessionToken"],
            }
        except ClientError as exc:
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _retry_on_propagation(fn, attempts: int = 15, delay_s: float = 3.0):
    """Retries ONLY the AccessDenied a just-assumed role's inline policy has not yet propagated;
    a call this check expects to succeed, never one it expects to fail."""
    last_exc: ClientError | None = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "AccessDenied":
                last_exc = exc
                time.sleep(delay_s)
                continue
            raise
    raise last_exc


def _denied(fn):
    """(Code, Message) of the ClientError `fn` raises; an unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be denied, but it succeeded: {result!r}")


def _rules(resp: dict) -> list[dict]:
    return resp["ServerSideEncryptionConfiguration"]["Rules"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A role allowed only to read a bucket's default encryption is refused PutBucketEncryption
    and the bucket's default SSE-S3 configuration stays in place; a twin role provisioned with
    the permission applies SSE-KMS, visible only through the independent read."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    bucket = _new_bucket(ctx, s3)
    bucket_arn = f"arn:aws:s3:::{bucket}"

    baseline = _rules(s3.get_bucket_encryption(Bucket=bucket))
    assert len(baseline) == 1 and baseline[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] == "AES256", (
        f"a freshly created bucket's default encryption was {baseline!r}, expected one AES256 rule"
    )

    ro_arn, ro_name = _role_with_actions(
        ctx, iam, "sim2real-putenc-ro-", ["s3:GetEncryptionConfiguration"], bucket_arn
    )
    rw_arn, rw_name = _role_with_actions(
        ctx, iam, "sim2real-putenc-rw-",
        ["s3:GetEncryptionConfiguration", "s3:PutEncryptionConfiguration"], bucket_arn,
    )

    ro_session = ctx.unique_name("sess-ro-")
    ro_client = ctx.client("s3", creds=_assumed_creds(ctx, ro_arn, ro_session))

    # Beat 1: positive control — the read-only role sees the same default the main session does.
    ro_read = _retry_on_propagation(lambda: _rules(ro_client.get_bucket_encryption(Bucket=bucket)))
    assert ro_read == baseline, f"the read-only role saw {ro_read!r}, expected the same {baseline!r}"

    # Beat 2: break exactly PutBucketEncryption and assert the specific denial.
    code, message = _denied(
        lambda: ro_client.put_bucket_encryption(Bucket=bucket, ServerSideEncryptionConfiguration=_KMS_CONFIG)
    )
    expected_message = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{ro_name}/{ro_session} is not "
        f"authorized to perform: s3:PutEncryptionConfiguration on resource: \"{bucket_arn}\" "
        "because no identity-based policy allows the s3:PutEncryptionConfiguration action"
    )
    assert code == "AccessDenied", f"PutBucketEncryption under the read-only role answered {code!r}"
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # Beat 3: the effect is absent — an independent read (the main session) still sees the
    # untouched default, not the KMS configuration the denied call tried to apply.
    unchanged = _rules(s3.get_bucket_encryption(Bucket=bucket))
    assert unchanged == baseline, (
        f"the bucket's default encryption changed to {unchanged!r} after a denied PutBucketEncryption"
    )

    # Beat 4/5: the twin role, provisioned with the permission from the start, applies SSE-KMS.
    rw_session = ctx.unique_name("sess-rw-")
    rw_client = ctx.client("s3", creds=_assumed_creds(ctx, rw_arn, rw_session))
    _retry_on_propagation(
        lambda: rw_client.put_bucket_encryption(
            Bucket=bucket, ServerSideEncryptionConfiguration=_KMS_CONFIG
        )
    )

    # Beat 6: an independent read confirms the new default, applied only by the permitted role.
    after = _rules(s3.get_bucket_encryption(Bucket=bucket))
    assert len(after) == 1, f"expected exactly one rule after the twin role's put, got {after!r}"
    applied = after[0]["ApplyServerSideEncryptionByDefault"]
    assert applied["SSEAlgorithm"] == "aws:kms", (
        f"default encryption after the twin role's PutBucketEncryption was {applied!r}, expected aws:kms"
    )
    assert after[0]["BucketKeyEnabled"] is True, f"expected BucketKeyEnabled, got {after[0]!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
