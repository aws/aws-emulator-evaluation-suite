"""file-system-lifecycle-creating-to-available."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "file-system-lifecycle-creating-to-available"
GROUP = "state"
SERVICES = ["s3files"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateFileSystem starts in 'creating' and transitions to 'available' with fields intact."""
    s3files = ctx.client("s3files")
    bucket = _create_versioned_bucket(ctx)
    role_arn = _create_s3files_role(ctx, bucket["name"])

    resp = _create_file_system_retrying(ctx, bucket["arn"], role_arn)
    fs_id = resp["fileSystemId"]
    ctx.on_cleanup(lambda: s3files.delete_file_system(fileSystemId=fs_id))

    assert resp["status"] == "creating", f"expected initial status 'creating', got {resp['status']!r}"
    assert resp["bucket"] == bucket["arn"], f"expected bucket {bucket['arn']!r} on create response, got {resp['bucket']!r}"
    assert resp["roleArn"] == role_arn, f"expected roleArn {role_arn!r} on create response, got {resp['roleArn']!r}"

    final = _poll_until(
        lambda: s3files.get_file_system(fileSystemId=fs_id),
        lambda r: r["status"] in ("available", "error"),
        timeout_s=300.0,
        interval_s=5.0,
    )
    assert final["status"] == "available", f"file system reached terminal status {final['status']!r} instead of 'available': {final.get('statusMessage')}"
    assert final["fileSystemId"] == fs_id, f"expected fileSystemId {fs_id!r} on independent read, got {final['fileSystemId']!r}"
    assert final["bucket"] == bucket["arn"], f"expected bucket {bucket['arn']!r} to survive the creating->available transition, got {final['bucket']!r}"
    assert final["roleArn"] == role_arn, f"expected roleArn {role_arn!r} to survive the creating->available transition, got {final['roleArn']!r}"


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_versioned_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-s3files-")
    kwargs = {"Bucket": name}
    # us-east-1 is S3's default region: CreateBucket rejects an explicit LocationConstraint there.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})

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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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


def _create_file_system_retrying(ctx, bucket_arn, role_arn, timeout_s=60.0, **kwargs):
    """CreateFileSystem right after IAM role creation can 404 on the role until it propagates."""
    s3files = ctx.client("s3files")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return s3files.create_file_system(
                bucket=bucket_arn, roleArn=role_arn,
                tags=[{"key": "sim2real-check", "value": CHECK}], **kwargs,
            )
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
