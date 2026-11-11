"""replication-server-side-execution."""

from __future__ import annotations
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "replication-server-side-execution"
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
    return name


def _new_versioned_bucket(ctx, s3):
    """Create a bucket with versioning Enabled (teardown registered)."""
    name = _new_bucket(ctx, s3)
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    return name


def _err_code(fn):
    """Call fn(); return botocore Error.Code if a ClientError is raised, else None."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return None


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy. Returns the final result."""
    deadline = time.monotonic() + timeout_s
    last_result = None
    while time.monotonic() < deadline:
        last_result = probe()
        if predicate(last_result):
            return last_result
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last_result!r}")


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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A configured replication rule causes PutObject writes to the source bucket to be replicated
    SERVER-SIDE into the destination bucket, with no client action beyond the original PutObject."""
    s3 = ctx.client("s3")
    source_bucket = _new_versioned_bucket(ctx, s3)
    dest_bucket = _new_versioned_bucket(ctx, s3)

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-repl-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "s3.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    perm_policy_name = "sim2real-behav-replication-policy"
    perm_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetReplicationConfiguration", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{source_bucket}"],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObjectVersionForReplication", "s3:GetObjectVersionAcl", "s3:GetObjectVersionTagging"],
                "Resource": [f"arn:aws:s3:::{source_bucket}/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"],
                "Resource": [f"arn:aws:s3:::{dest_bucket}/*"],
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=perm_policy_name, PolicyDocument=json.dumps(perm_policy))
    ctx.on_cleanup(lambda: _delete_role(iam, role_name, perm_policy_name))

    replication_config = {
        "Role": role_arn,
        "Rules": [
            {
                "ID": "sim2real-repl-rule",
                "Status": "Enabled",
                "Priority": 1,
                "Filter": {"Prefix": ""},
                "DeleteMarkerReplication": {"Status": "Disabled"},
                "Destination": {"Bucket": f"arn:aws:s3:::{dest_bucket}"},
            }
        ],
    }

    def _put_replication():
        return _err_code(
            lambda: s3.put_bucket_replication(Bucket=source_bucket, ReplicationConfiguration=replication_config)
        )

    # IAM role trust-policy propagation to S3's replication engine can lag a few seconds.
    _poll_until(
        _put_replication,
        lambda code: code is None,
        timeout_s=60,
        interval_s=3,
        description="PutBucketReplication to accept the freshly-created replication role",
    )

    got = s3.get_bucket_replication(Bucket=source_bucket)
    rules = got["ReplicationConfiguration"]["Rules"]
    assert any(
        r["Destination"]["Bucket"] == f"arn:aws:s3:::{dest_bucket}" for r in rules
    ), f"expected the destination bucket reflected in GetBucketReplication, got {rules}"

    key = "replicate-me.txt"
    data = b"server-side-replicated-payload"
    s3.put_object(Bucket=source_bucket, Key=key, Body=data)

    def _dest_head_code():
        return _err_code(lambda: s3.head_object(Bucket=dest_bucket, Key=key))

    # Cross-bucket replication is asynchronous; small objects usually land within
    # seconds to low minutes, but this is generous to absorb queueing jitter.
    _poll_until(
        _dest_head_code,
        lambda code: code is None,
        timeout_s=300,
        interval_s=10,
        description="PutObject to be server-side replicated into the destination bucket",
    )

    replicated = s3.get_object(Bucket=dest_bucket, Key=key)["Body"].read()
    assert replicated == data, "the replicated object body must match the source exactly, with no client re-upload"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
