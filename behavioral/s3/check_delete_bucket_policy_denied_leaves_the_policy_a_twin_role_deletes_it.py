"""delete-bucket-policy-denied-leaves-the-policy-a-twin-role-deletes-it."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-bucket-policy-denied-leaves-the-policy-a-twin-role-deletes-it"
GROUP = "auth_enforcement"
SERVICES = ["s3", "iam", "sts"]


def _delete_bucket(s3, bucket: str) -> None:
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3) -> str:
    name = ctx.unique_name("sim2real-delpol-")
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


def _spun_up_role(ctx, iam, name_prefix: str, statements: list[dict]) -> tuple[str, str]:
    """A role this account's root can assume, carrying one inline policy. Returns
    (role_arn, role_name); teardown is registered."""
    role_name = ctx.unique_name(name_prefix)
    policy_name = f"{role_name}-perms"
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
            "Action": "sts:AssumeRole",
        }],
    }
    created = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: _remove_role(iam, role_name, policy_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
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


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A role allowed only to read a bucket policy is refused DeleteBucketPolicy and leaves the
    policy intact; a twin role provisioned with the delete permission at the same time deletes it,
    pinning the refusal to the missing permission rather than the bucket or the policy."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    bucket = _new_bucket(ctx, s3)

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowRootFullControl",
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/*",
        }],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy_doc))

    bucket_arn = f"arn:aws:s3:::{bucket}"
    ro_arn, ro_name = _spun_up_role(
        ctx, iam, "sim2real-delpol-ro-",
        [{"Effect": "Allow", "Action": "s3:GetBucketPolicy", "Resource": bucket_arn}],
    )
    rw_arn, rw_name = _spun_up_role(
        ctx, iam, "sim2real-delpol-rw-",
        [
            {"Effect": "Allow", "Action": "s3:GetBucketPolicy", "Resource": bucket_arn},
            {"Effect": "Allow", "Action": "s3:DeleteBucketPolicy", "Resource": bucket_arn},
        ],
    )

    ro_session = ctx.unique_name("sess-ro-")
    ro_client = ctx.client("s3", creds=_assumed_creds(ctx, ro_arn, ro_session))

    # Beat 1: positive control — the read-only role can read the policy it cannot delete.
    read_back = _retry_on_propagation(lambda: ro_client.get_bucket_policy(Bucket=bucket))
    assert json.loads(read_back["Policy"]) == policy_doc, (
        f"GetBucketPolicy under the read-only role returned {read_back['Policy']!r}, "
        f"expected the policy just put"
    )

    # Beat 2: break exactly DeleteBucketPolicy and assert the specific denial.
    code, message = _denied(lambda: ro_client.delete_bucket_policy(Bucket=bucket))
    expected_message = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{ro_name}/{ro_session} is not "
        f"authorized to perform: s3:DeleteBucketPolicy on resource: \"{bucket_arn}\" "
        "because no identity-based policy allows the s3:DeleteBucketPolicy action"
    )
    assert code == "AccessDenied", f"DeleteBucketPolicy under the read-only role answered {code!r}"
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # Beat 3: the effect is absent — an independent read (the main session) sees the policy
    # untouched by the denied attempt.
    still_there = s3.get_bucket_policy(Bucket=bucket)
    assert json.loads(still_there["Policy"]) == policy_doc, (
        f"the bucket policy changed after a denied DeleteBucketPolicy: {still_there['Policy']!r}"
    )

    # Beat 4/5: the twin role, provisioned with the delete permission from the start, performs
    # the identical delete successfully — pinning the refusal to the missing permission alone.
    rw_session = ctx.unique_name("sess-rw-")
    rw_client = ctx.client("s3", creds=_assumed_creds(ctx, rw_arn, rw_session))
    _retry_on_propagation(lambda: rw_client.delete_bucket_policy(Bucket=bucket))

    # Beat 6: an independent read confirms the policy is gone.
    gone_code, _ = _denied(lambda: s3.get_bucket_policy(Bucket=bucket))
    assert gone_code == "NoSuchBucketPolicy", (
        f"GetBucketPolicy after the twin role's delete returned {gone_code!r}, "
        "expected NoSuchBucketPolicy"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
