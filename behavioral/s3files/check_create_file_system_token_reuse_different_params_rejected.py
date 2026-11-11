"""create-file-system-token-reuse-different-params-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-file-system-token-reuse-different-params-rejected"
GROUP = "overly-permissive"
SERVICES = ["s3files"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Reusing a clientToken with different CreateFileSystem parameters is rejected; reusing it identically is
    ALSO rejected — this service's clientToken is a single-use dedupe guard, not an idempotent-replay token."""
    s3files = ctx.client("s3files")
    bucket1 = _create_versioned_bucket(ctx)
    bucket2 = _create_versioned_bucket(ctx)
    role_arn = _create_s3files_role(ctx, bucket1["name"])
    role_arn2 = _create_s3files_role(ctx, bucket2["name"])
    token = ctx.unique_name("sim2real-s3files-token-")

    first = _create_retrying(
        ctx, bucket=bucket1["arn"], roleArn=role_arn, clientToken=token, tags=[{"key": "sim2real", "value": CHECK}],
    )
    fs_id = first["fileSystemId"]
    ctx.on_cleanup(lambda: _delete_file_system_and_wait(s3files, fs_id))

    # Same token, a *different* bucket/role -> the request must be rejected, not silently accepted.
    code, message = _error(lambda: s3files.create_file_system(
        bucket=bucket2["arn"], roleArn=role_arn2, clientToken=token, tags=[{"key": "sim2real", "value": CHECK}],
    ))
    assert code == "ConflictException", f"expected ConflictException for a clientToken reused with different params, got {code!r}"
    expected_message = f"File system '{fs_id}' already exists with this clientToken."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: no second file system was created for bucket2 (still only the original exists for it).
    listing = s3files.list_file_systems(bucket=bucket2["arn"])["fileSystems"]
    assert listing == [], f"expected no file system to have been created for bucket2, got {listing}"

    # Positive control boundary: even an *identical* retry with the same clientToken is rejected once the
    # token has been consumed — it is not honored as an idempotent replay.
    retry_code, retry_message = _error(lambda: s3files.create_file_system(
        bucket=bucket1["arn"], roleArn=role_arn, clientToken=token, tags=[{"key": "sim2real", "value": CHECK}],
    ))
    assert retry_code == "ConflictException", (
        f"expected reusing a clientToken (even with identical params) to be rejected, got {retry_code!r}"
    )
    assert retry_message == expected_message, f"expected message {expected_message!r}, got {retry_message!r}"

    # Terminal read, independent of the mutating create calls: bucket1 still has exactly the one file
    # system the first call created — the identical-token retry did not spawn a second one either.
    listed_for_bucket1 = {fs["fileSystemId"] for fs in s3files.list_file_systems(bucket=bucket1["arn"])["fileSystems"]}
    assert listed_for_bucket1 == {fs_id}, f"expected only the original file system for bucket1, got {listed_for_bucket1}"


def _error(fn):
    """Return the (code, message) of the ClientError ``fn`` raises; a success is an AssertionError."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _delete_file_system_and_wait(s3files, fs_id, *, timeout_s=300.0, interval_s=5.0):
    """Teardown: delete the file system, tolerating not-found, and wait until it is gone so its bucket can go."""
    try:
        s3files.delete_file_system(fileSystemId=fs_id)
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            s3files.get_file_system(fileSystemId=fs_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"file system {fs_id} still present {timeout_s}s after delete")


def _create_versioned_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-s3files-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=name):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])]
            if objs:
                s3.delete_objects(Bucket=name, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return {"name": name, "arn": f"arn:aws:s3:::{name}"}


def _create_s3files_role(ctx, bucket_name):
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-s3files-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowS3FilesAssumeRole",
            "Effect": "Allow",
            "Principal": {"Service": "elasticfilesystem.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "S3Access",
            "Effect": "Allow",
            "Action": ["s3:ListBucket", "s3:ListBucketVersions", "s3:GetObject*", "s3:PutObject*",
                       "s3:DeleteObject*", "s3:AbortMultipartUpload"],
            "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="s3files-access", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3files-access"))
    return role_arn


def _create_retrying(ctx, **kwargs):
    s3files = ctx.client("s3files")
    deadline = time.monotonic() + 60.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            return s3files.create_file_system(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ResourceNotFoundException", "ValidationException"):
                last_err = err
                time.sleep(3)
                continue
            raise
    raise last_err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
