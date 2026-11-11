"""bucket-replication-roundtrip."""

from __future__ import annotations
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "bucket-replication-roundtrip"
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
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
    return name


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _retry_until_success(fn, *, timeout_s=60, interval_s=1.0, description="call"):
    """Call fn() until it stops raising ClientError; raise AssertionError at the deadline."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            fn()
            return
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"{description} did not succeed within {timeout_s}s: {last_exc}") from last_exc


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
    """Create a minimal IAM role S3 can assume for cross-bucket replication, with an inline
    permissions policy scoped to the two buckets. Returns the role ARN; teardown registered."""
    role_name = ctx.unique_name("sim2real-behav-repl-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "s3.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
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


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutBucketReplication configuration is retrievable and removable via DeleteBucketReplication.

    Requires versioning enabled on both source and destination, and a real IAM role S3 can assume
    (iam:PassRole validates the role actually exists).
    """
    s3 = ctx.client("s3")
    src = _new_bucket(ctx, s3)
    dst = _new_bucket(ctx, s3)
    s3.put_bucket_versioning(Bucket=src, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_versioning(Bucket=dst, VersioningConfiguration={"Status": "Enabled"})

    role_arn = _create_replication_role(ctx, ctx.client("iam"), src, dst)

    rule = {
        "ID": "sim2real-rule",
        "Status": "Enabled",
        "Priority": 1,
        "Filter": {"Prefix": ""},
        "DeleteMarkerReplication": {"Status": "Disabled"},
        "Destination": {"Bucket": f"arn:aws:s3:::{dst}"},
    }

    def _put_replication():
        s3.put_bucket_replication(
            Bucket=src, ReplicationConfiguration={"Role": role_arn, "Rules": [rule]}
        )

    # A freshly-created IAM role can take a few seconds to become assumable by S3;
    # retry until PutBucketReplication stops rejecting it.
    _retry_until_success(
        _put_replication,
        timeout_s=60,
        interval_s=3,
        description="PutBucketReplication to accept the freshly-created IAM role",
    )

    fetched = s3.get_bucket_replication(Bucket=src)["ReplicationConfiguration"]
    assert fetched["Role"] == role_arn, f"expected Role {role_arn!r}, got {fetched.get('Role')!r}"
    assert len(fetched["Rules"]) == 1, f"expected exactly 1 rule, got {fetched['Rules']!r}"
    fetched_rule = fetched["Rules"][0]
    assert fetched_rule["Status"] == "Enabled", f"expected rule Status 'Enabled', got {fetched_rule.get('Status')!r}"
    assert fetched_rule["Destination"]["Bucket"] == f"arn:aws:s3:::{dst}", (
        f"expected destination bucket arn:aws:s3:::{dst}, got {fetched_rule['Destination'].get('Bucket')!r}"
    )

    s3.delete_bucket_replication(Bucket=src)
    code, message = _error(lambda: s3.get_bucket_replication(Bucket=src))
    assert code == "ReplicationConfigurationNotFoundError", (
        f"expected ReplicationConfigurationNotFoundError after delete, got {code}"
    )
    assert message == "The replication configuration was not found", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
