"""get-bucket-replication-not-configured-rejected."""

from __future__ import annotations
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "get-bucket-replication-not-configured-rejected"
GROUP = 'replication'
SERVICES = ['s3']


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; best-effort teardown."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                client.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3, **kwargs):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    # us-east-1 is the only region CreateBucket rejects a LocationConstraint for.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _rejects(fn):
    """Call fn(); return the botocore Error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_role(iam, role_name, policy_name):
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


def _create_replication_role(ctx, iam, src_bucket, dst_bucket):
    """Create an IAM role S3 can assume for replication between the two buckets; return its ARN."""
    role_name = ctx.unique_name("sim2real-behav-repl-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "s3.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetReplicationConfiguration", "s3:ListBucket"],
                "Resource": f"arn:aws:s3:::{src_bucket}",
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObjectVersionForReplication",
                    "s3:GetObjectVersionAcl",
                    "s3:GetObjectVersionTagging",
                ],
                "Resource": f"arn:aws:s3:::{src_bucket}/*",
            },
            {
                "Effect": "Allow",
                "Action": ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"],
                "Resource": f"arn:aws:s3:::{dst_bucket}/*",
            },
        ],
    }
    policy_name = "sim2real-behav-repl-policy"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: _delete_role(iam, role_name, policy_name))
    return role_arn


def _put_replication_with_retry(fn, *, timeout_s=60.0, interval_s=3.0):
    """Retry fn() while it raises AccessDenied/MalformedPolicy/InvalidRequest: a new IAM role
    takes a few seconds to become assumable by S3."""
    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("AccessDenied", "MalformedPolicy", "InvalidRequest"):
                raise
            last_error = exc
            time.sleep(interval_s)
    raise AssertionError(f"PutBucketReplication never accepted the freshly-created role: {last_error}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetBucketReplication on a versioned bucket with no replication config fails with
    ReplicationConfigurationNotFoundError; once one is set, the same call returns it."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    src = _new_bucket(ctx, s3)
    s3.put_bucket_versioning(Bucket=src, VersioningConfiguration={"Status": "Enabled"})

    never_configured = _rejects(lambda: s3.get_bucket_replication(Bucket=src))
    assert never_configured.get("Code") == "ReplicationConfigurationNotFoundError", (
        f"expected ReplicationConfigurationNotFoundError, got {never_configured!r}"
    )
    assert never_configured.get("Message") == "The replication configuration was not found", (
        never_configured.get("Message")
    )

    dst = _new_bucket(ctx, s3)
    s3.put_bucket_versioning(Bucket=dst, VersioningConfiguration={"Status": "Enabled"})
    dst_arn = f"arn:aws:s3:::{dst}"
    role_arn = _create_replication_role(ctx, iam, src, dst)

    replication_config = {
        "Role": role_arn,
        "Rules": [
            {
                "ID": "sim2real-rule",
                "Status": "Enabled",
                "Priority": 1,
                "Filter": {"Prefix": ""},
                "DeleteMarkerReplication": {"Status": "Disabled"},
                "Destination": {"Bucket": dst_arn},
            }
        ],
    }
    _put_replication_with_retry(
        lambda: s3.put_bucket_replication(Bucket=src, ReplicationConfiguration=replication_config)
    )

    now_configured = s3.get_bucket_replication(Bucket=src)["ReplicationConfiguration"]
    assert now_configured["Role"] == role_arn, now_configured
    assert now_configured["Rules"][0]["Status"] == "Enabled", now_configured
    assert now_configured["Rules"][0]["Destination"]["Bucket"] == dst_arn, now_configured


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
