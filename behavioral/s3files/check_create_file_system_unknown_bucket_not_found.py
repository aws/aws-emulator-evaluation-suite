"""create-file-system-unknown-bucket-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-file-system-unknown-bucket-not-found"
GROUP = "error-semantics"
SERVICES = ["s3files"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFileSystem for a well-formed but nonexistent bucket ARN is ResourceNotFoundException "The
    bucket you specified does not exist." and lists no file system for it, while after that bucket is
    created the same call succeeds and the file system appears in ListFileSystems."""
    s3files = ctx.client("s3files")
    role_arn = _create_s3files_role(ctx)
    bucket_name = ctx.unique_name("sim2real-s3files-ghost-")
    bucket_arn = f"arn:aws:s3:::{bucket_name}"

    code, message = _error(lambda: s3files.create_file_system(bucket=bucket_arn, roleArn=role_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == "The bucket you specified does not exist.", (
        f"expected message 'The bucket you specified does not exist.', got {message!r}"
    )

    listed_before = {fs["fileSystemId"] for fs in s3files.list_file_systems(bucket=bucket_arn)["fileSystems"]}
    assert listed_before == set(), f"expected no file system for the nonexistent bucket, found {listed_before}"

    _create_versioned_bucket_named(ctx, bucket_name)
    resp = _create_file_system_retrying(ctx, bucket_arn, role_arn)
    fs_id = resp["fileSystemId"]
    ctx.on_cleanup(lambda: _delete_file_system_and_wait(s3files, fs_id))
    assert resp["bucket"] == bucket_arn, f"expected the now-real bucket to be accepted, got {resp['bucket']!r}"

    listed_after = {fs["fileSystemId"] for fs in s3files.list_file_systems(bucket=bucket_arn)["fileSystems"]}
    assert fs_id in listed_after, f"expected {fs_id} to now appear in ListFileSystems for {bucket_arn}, got {listed_after}"


def _error(fn):
    """Return the (code, message) of the ClientError ``fn`` raises; a success is an AssertionError."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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


def _create_versioned_bucket_named(ctx, name):
    s3 = ctx.client("s3")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})

    def _cleanup():
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=name):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])]
            if objs:
                s3.delete_objects(Bucket=name, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)


def _create_file_system_retrying(ctx, bucket_arn, role_arn, timeout_s=60.0, **kwargs):
    """CreateFileSystem right after S3 bucket creation can 404 until the bucket propagates."""
    s3files = ctx.client("s3files")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return s3files.create_file_system(bucket=bucket_arn, roleArn=role_arn, **kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ResourceNotFoundException", "ValidationException"):
                last_err = err
                time.sleep(3)
                continue
            raise
    raise last_err


def _create_s3files_role(ctx):
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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
