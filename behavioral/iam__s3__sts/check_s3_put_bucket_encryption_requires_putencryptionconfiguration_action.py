"""s3-put-bucket-encryption-requires-putencryptionconfiguration-action."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-put-bucket-encryption-requires-putencryptionconfiguration-action"
GROUP = "auth_enforcement"
SERVICES = ["iam", "s3", "sts"]

# A new bucket already defaults to SSE-S3 (AES256), so the allowed write switches the default to
# SSE-KMS with the AWS managed key and the refused write tries to switch it back.
_KMS_CONFIG = {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]}
_AES256_CONFIG = {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}


def _new_bucket(ctx, s3):
    """Create a uniquely-named bucket and register its teardown; return its name."""
    name = ctx.unique_name("sim2real-behav-penc-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _delete_bucket(s3, bucket: str) -> None:
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _delete_role(iam, role_name: str, policy_name: str) -> None:
    def run_undo() -> None:
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

    return run_undo


def _create_assumable_role(ctx, iam, role_prefix: str, bucket: str, action: str):
    """Create a role, trusted by this account's root, with an inline policy granting `action` on
    `bucket`. Returns (role_arn, role_name); teardown is registered."""
    role_name = ctx.unique_name(role_prefix)
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
             "Action": "sts:AssumeRole"}
        ],
    }
    policy_name = f"{role_name}-perms"
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(_delete_role(iam, role_name, policy_name))
    role_arn = resp["Role"]["Arn"]
    permission_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": action, "Resource": f"arn:aws:s3:::{bucket}"}
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name,
                         PolicyDocument=json.dumps(permission_policy))
    return role_arn, role_name


def _assume_role_client(ctx, role_arn: str, service: str, session_name: str, max_attempts: int = 12):
    """AssumeRole as `session_name` (retrying while IAM propagates) and return a `service` client
    built from the temporary credentials, verified first with a throwaway GetCallerIdentity."""
    sts = ctx.client("sts")
    creds = None
    last_exc = None
    for _ in range(max_attempts):
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
            break
        except ClientError as exc:
            last_exc = exc
            time.sleep(2)
    if creds is None:
        raise last_exc

    cred_kwargs = {
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    }
    probe = ctx.client("sts", creds=cred_kwargs)
    probe_exc = None
    for _ in range(max_attempts):
        try:
            probe.get_caller_identity()
            probe_exc = None
            break
        except ClientError as exc:
            probe_exc = exc
            time.sleep(2)
    if probe_exc is not None:
        raise probe_exc
    return ctx.client(service, creds=cred_kwargs)


def _access_denied_retry(fn, attempts: int = 10, delay_s: float = 3.0):
    """A freshly attached inline policy can lag AssumeRole's own propagation; retry an unexpected
    AccessDenied on a call the check expects to SUCCEED, never on one it expects to fail."""
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            err = exc.response.get("Error", {})
            if err.get("Code") == "AccessDenied" or (err.get("Code"), err.get("Message")) == _KEY_NOT_YET:
                time.sleep(delay_s)
                continue
            raise
    raise last_exc


def _sse_algorithm(s3, bucket: str) -> str:
    """The bucket's default SSEAlgorithm from GetBucketEncryption's first rule."""
    rules = s3.get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"]["Rules"]
    return rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]


_KEY_NOT_YET = ("InvalidAccessKeyId", "The AWS Access Key Id you provided does not exist in our records.")


def _error(fn, attempts: int = 20, delay_s: float = 3.0):
    """(Error.Code, Error.Message) of the ClientError fn() raises, retrying only while a fresh
    session's key is not yet known to S3; an unexpected success fails."""
    for _ in range(attempts):
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            pair = (err.get("Code"), err.get("Message"))
            if pair != _KEY_NOT_YET:
                return pair
            time.sleep(delay_s)
            continue
        raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")
    return _KEY_NOT_YET


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutBucketEncryption is authorized by the s3:PutEncryptionConfiguration IAM action, not by
    an identity-policy statement naming the operation name s3:PutBucketEncryption literally.
    """
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    bucket = _new_bucket(ctx, s3)
    got = _sse_algorithm(s3, bucket)
    assert got == "AES256", f"a new bucket's default SSEAlgorithm is {got!r}; expected 'AES256'"

    allowed_arn, allowed_name = _create_assumable_role(
        ctx, iam, "sim2real-behav-penc-allow-", bucket, "s3:PutEncryptionConfiguration"
    )
    denied_arn, denied_name = _create_assumable_role(
        ctx, iam, "sim2real-behav-penc-deny-", bucket, "s3:PutBucketEncryption"
    )

    allowed_session = ctx.unique_name("sess-allow-")
    allowed_client = _assume_role_client(ctx, allowed_arn, "s3", allowed_session)

    # --- Positive control: the role granted the real IAM action name can call the operation.
    _access_denied_retry(
        lambda: allowed_client.put_bucket_encryption(
            Bucket=bucket, ServerSideEncryptionConfiguration=_KMS_CONFIG
        )
    )
    got = _sse_algorithm(s3, bucket)
    assert got == "aws:kms", (
        f"GetBucketEncryption's SSEAlgorithm is {got!r} after the allowed role's "
        "PutBucketEncryption; expected 'aws:kms'"
    )

    denied_session = ctx.unique_name("sess-deny-")
    denied_client = _assume_role_client(ctx, denied_arn, "s3", denied_session)

    expected_message = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{denied_name}/{denied_session} is not "
        f'authorized to perform: s3:PutEncryptionConfiguration on resource: "arn:aws:s3:::{bucket}" '
        "because no identity-based policy allows the s3:PutEncryptionConfiguration action"
    )
    code, message = _error(
        lambda: denied_client.put_bucket_encryption(
            Bucket=bucket, ServerSideEncryptionConfiguration=_AES256_CONFIG
        )
    )
    assert code == "AccessDenied", (
        f"the role granted only the operation-named action s3:PutBucketEncryption got {code!r}; "
        "expected AccessDenied"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The denied call left the configuration from the allowed role's write untouched.
    got = _sse_algorithm(s3, bucket)
    assert got == "aws:kms", (
        f"GetBucketEncryption's SSEAlgorithm is {got!r} after the refused call; "
        "expected the prior 'aws:kms' to be unchanged"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
