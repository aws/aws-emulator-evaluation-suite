"""put-synchronization-configuration-multiple-expiration-rules-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-synchronization-configuration-multiple-expiration-rules-rejected"
GROUP = "overly-permissive"
SERVICES = ["s3files"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutSynchronizationConfiguration with more than one expirationDataRule is rejected (exactly 1 is required)."""
    s3files = ctx.client("s3files")
    bucket = _create_versioned_bucket(ctx)
    role_arn = _create_s3files_role(ctx, bucket["name"])
    fs_id = _create_and_wait_available(ctx, bucket["arn"], role_arn)

    code, message = _error(lambda: s3files.put_synchronization_configuration(
        fileSystemId=fs_id,
        importDataRules=[{"prefix": "", "trigger": "ON_FILE_ACCESS", "sizeLessThan": 1048576}],
        expirationDataRules=[{"daysAfterLastAccess": 30}, {"daysAfterLastAccess": 60}],
    ))
    assert code == "ValidationException", f"expected ValidationException for 2 expirationDataRules, got {code!r}"
    expected_message = (
        "1 validation error detected: Value '[ExpirationDataRule(daysAfterLastAccess=30), "
        "ExpirationDataRule(daysAfterLastAccess=60)]' at 'expirationDataRules' failed to satisfy constraint: "
        "Member must have length less than or equal to 1"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the rejected 2-rule put must never have been persisted. A file system that has
    # never had a configuration put still answers GetSynchronizationConfiguration with its default.
    before = s3files.get_synchronization_configuration(fileSystemId=fs_id)
    assert before.get("expirationDataRules") != [{"daysAfterLastAccess": 30}, {"daysAfterLastAccess": 60}], (
        f"the rejected 2-rule expirationDataRules must never have been persisted, got {before}"
    )

    # Positive control: exactly one expirationDataRule succeeds.
    s3files.put_synchronization_configuration(
        fileSystemId=fs_id,
        importDataRules=[{"prefix": "", "trigger": "ON_FILE_ACCESS", "sizeLessThan": 1048576}],
        expirationDataRules=[{"daysAfterLastAccess": 30}],
    )
    fetched = s3files.get_synchronization_configuration(fileSystemId=fs_id)
    assert fetched["expirationDataRules"] == [{"daysAfterLastAccess": 30}], (
        f"expected the single-rule put to persist exactly, got {fetched['expirationDataRules']!r}"
    )


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
    if ctx.region != "us-east-1":
        # us-east-1 is S3's CreateBucket special case: it rejects an explicit LocationConstraint
        # for its own region, so the literal here tracks S3's API contract, not this check's region.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})

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
        Tags=[{"Key": "sim2real", "Value": "true"}],
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


def _create_and_wait_available(ctx, bucket_arn, role_arn, **kwargs):
    s3files = ctx.client("s3files")
    deadline = time.monotonic() + 60.0
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = s3files.create_file_system(
                bucket=bucket_arn, roleArn=role_arn,
                tags=[{"key": "sim2real", "value": "true"}], **kwargs,
            )
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ResourceNotFoundException", "ValidationException"):
                last_err = err
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise last_err
    fs_id = resp["fileSystemId"]
    ctx.on_cleanup(lambda: _delete_file_system_and_wait(s3files, fs_id))
    _poll_until(
        lambda: s3files.get_file_system(fileSystemId=fs_id)["status"],
        lambda s: s == "available",
        timeout_s=300.0,
        interval_s=5.0,
    )
    return fs_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
