"""synchronization-configuration-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "synchronization-configuration-round-trip"
GROUP = "data-plane"
SERVICES = ["s3files"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutSynchronizationConfiguration persists exact import/expiration rules and increments the version on update."""
    s3files = ctx.client("s3files")
    bucket = _create_versioned_bucket(ctx)
    role_arn = _create_s3files_role(ctx, bucket["name"])
    fs_id = _create_and_wait_available(ctx, bucket["arn"], role_arn)

    import_rules_v1 = [
        {"prefix": "", "trigger": "ON_FILE_ACCESS", "sizeLessThan": 1048576},
        {"prefix": "archive/", "trigger": "ON_DIRECTORY_FIRST_ACCESS", "sizeLessThan": 10485760},
    ]
    expiration_rules_v1 = [{"daysAfterLastAccess": 7}]

    put1 = s3files.put_synchronization_configuration(
        fileSystemId=fs_id, importDataRules=import_rules_v1, expirationDataRules=expiration_rules_v1,
    )
    extra_fields_1 = {k for k in put1 if k != "ResponseMetadata"}
    assert not extra_fields_1, f"expected PutSynchronizationConfiguration to return an empty body, got fields: {extra_fields_1}"

    fetched1 = s3files.get_synchronization_configuration(fileSystemId=fs_id)
    v1 = fetched1["latestVersionNumber"]
    assert sorted(fetched1["importDataRules"], key=lambda r: r["prefix"]) == sorted(import_rules_v1, key=lambda r: r["prefix"])
    assert fetched1["expirationDataRules"] == expiration_rules_v1

    # Every importDataRules payload must keep a rule for the root prefix ''; AWS answers
    # ValidationException without it.
    import_rules_v2 = [
        {"prefix": "", "trigger": "ON_DIRECTORY_FIRST_ACCESS", "sizeLessThan": 4096},
        {"prefix": "hot/", "trigger": "ON_FILE_ACCESS", "sizeLessThan": 4096},
    ]
    expiration_rules_v2 = [{"daysAfterLastAccess": 365}]
    put2 = s3files.put_synchronization_configuration(
        fileSystemId=fs_id, latestVersionNumber=v1,
        importDataRules=import_rules_v2, expirationDataRules=expiration_rules_v2,
    )
    extra_fields_2 = {k for k in put2 if k != "ResponseMetadata"}
    assert not extra_fields_2, f"expected PutSynchronizationConfiguration to return an empty body, got fields: {extra_fields_2}"

    fetched2 = s3files.get_synchronization_configuration(fileSystemId=fs_id)
    v2 = fetched2["latestVersionNumber"]
    assert v2 != v1, "expected the version number to change after a successful update"
    assert sorted(fetched2["importDataRules"], key=lambda r: r["prefix"]) == sorted(import_rules_v2, key=lambda r: r["prefix"])
    assert fetched2["expirationDataRules"] == expiration_rules_v2


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
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "env", "Value": "sim2real-behavioral"}]})

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
        Tags=[{"Key": "env", "Value": "sim2real-behavioral"}],
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
                tags=[{"key": "env", "value": "sim2real-behavioral"}], **kwargs,
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
    ctx.on_cleanup(lambda: s3files.delete_file_system(fileSystemId=fs_id))
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
