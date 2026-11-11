"""s3-replication-role-trust-s3-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "s3-replication-role-trust-s3-positive"
GROUP = "iam-trust"
SERVICES = ["cloudformation", "dynamodb", "s3"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A role trusted by s3.amazonaws.com is accepted by PutBucketReplication, round-trips via
    GetBucketReplication, and an object written to the source replicates to the destination."""
    s3 = ctx.client("s3")

    source = ctx.unique_name("sim2real-s3repl-src-")
    dest = ctx.unique_name("sim2real-s3repl-dst-")
    _create_versioned_bucket(ctx, source)
    _create_versioned_bucket(ctx, dest)

    role_arn = _create_replication_role(ctx, source, dest, name_hint="s3repl-role")

    rule_id = "sim2real-replicate-all"
    s3.put_bucket_replication(
        Bucket=source,
        ReplicationConfiguration={
            "Role": role_arn,
            "Rules": [
                {
                    "ID": rule_id,
                    "Status": "Enabled",
                    "Priority": 1,
                    "Filter": {"Prefix": ""},
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                    "Destination": {"Bucket": f"arn:aws:s3:::{dest}"},
                }
            ],
        },
    )

    got = s3.get_bucket_replication(Bucket=source)["ReplicationConfiguration"]
    assert got["Role"] == role_arn, f"expected persisted Role {role_arn!r}, got {got.get('Role')!r}"
    assert got["Rules"][0]["ID"] == rule_id, f"expected rule ID {rule_id!r}, got {got['Rules'][0].get('ID')!r}"
    assert got["Rules"][0]["Status"] == "Enabled", f"expected rule Status 'Enabled', got {got['Rules'][0].get('Status')!r}"

    key = "replicated/hello.txt"
    body = b"sim2real replication payload"
    s3.put_object(Bucket=source, Key=key, Body=body)

    replica = _wait_for_replica(ctx, dest, key, timeout_s=300)
    assert replica == body, "replicated object body mismatch"


def _create_versioned_bucket(ctx: Any, name: str) -> str:
    s3 = ctx.client("s3")
    kwargs: dict = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    return name


def _empty_and_delete_bucket(ctx: Any, name: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=name):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])]
            if objs:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_replication_role(ctx: Any, source_bucket: str, dest_bucket: str, name_hint: str) -> str:
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name(f"sim2real-{name_hint}-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "s3.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    permission_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetReplicationConfiguration", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{source_bucket}"],
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObjectVersionForReplication",
                    "s3:GetObjectVersionAcl",
                    "s3:GetObjectVersionTagging",
                ],
                "Resource": [f"arn:aws:s3:::{source_bucket}/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"],
                "Resource": f"arn:aws:s3:::{dest_bucket}/*",
            },
        ],
    }
    policy_name = "replication-policy"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(permission_policy))

    def _cleanup():
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

    ctx.on_cleanup(_cleanup)
    return role_arn


def _wait_for_replica(ctx: Any, bucket: str, key: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> bytes:
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        except Exception as e:  # NoSuchKey while replication is pending
            last_exc = e
            time.sleep(interval_s)
    raise AssertionError(f"object {key!r} never replicated into {bucket!r} within {timeout_s}s: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
