"""s3-replication-role-trusts-s3-service."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "s3-replication-role-trusts-s3-service"
GROUP = "permission-boundary"
SERVICES = ["events", "firehose", "s3"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutBucketReplication accepts a role that trusts s3.amazonaws.com, and a new object
    replicates end to end: its status reaches COMPLETED and the destination holds the exact same
    bytes."""
    s3 = ctx.client("s3")

    src = _create_versioned_bucket(ctx, "sim2real-s3-src-ok-")
    dst = _create_versioned_bucket(ctx, "sim2real-s3-dst-ok-")
    role_arn = _create_role(ctx, "s3.amazonaws.com", _replication_policy(src, dst))

    s3.put_bucket_replication(
        Bucket=src,
        ReplicationConfiguration={
            "Role": role_arn,
            "Rules": [_replication_rule(dst)],
        },
    )

    key = "sim2real-object.txt"
    marker = ctx.unique_name("sim2real-marker-")
    s3.put_object(Bucket=src, Key=key, Body=marker.encode())

    status = _poll_replication_status(s3, src, key, {"COMPLETED", "FAILED"}, timeout_s=300)
    assert status == "COMPLETED", f"expected replication status COMPLETED, got {status!r}"

    replica = s3.get_object(Bucket=dst, Key=key)["Body"].read().decode()
    assert replica == marker, f"expected replica body {marker!r} at destination, got {replica!r}"


def _create_versioned_bucket(ctx, prefix: str) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix)
    kwargs: dict[str, Any] = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "s3-replication-role-trusts-s3-service"}]})
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    return bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
        objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
    s3.delete_bucket(Bucket=bucket)


def _create_role(ctx, trust_service: str, permissions: dict) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "s3-replication-role-trusts-s3-service"}],
    )
    role_arn = resp["Role"]["Arn"]
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(permissions))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _replication_policy(src: str, dst: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetReplicationConfiguration", "s3:ListBucket"],
                "Resource": f"arn:aws:s3:::{src}",
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObjectVersionForReplication",
                    "s3:GetObjectVersionAcl",
                    "s3:GetObjectVersionTagging",
                ],
                "Resource": f"arn:aws:s3:::{src}/*",
            },
            {
                "Effect": "Allow",
                "Action": ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"],
                "Resource": f"arn:aws:s3:::{dst}/*",
            },
        ],
    }


def _replication_rule(dst: str) -> dict:
    return {
        "ID": "rule1",
        "Status": "Enabled",
        "Priority": 1,
        "Filter": {"Prefix": ""},
        "DeleteMarkerReplication": {"Status": "Disabled"},
        "Destination": {"Bucket": f"arn:aws:s3:::{dst}"},
    }


def _poll_replication_status(s3, bucket: str, key: str, terminal_statuses: set, timeout_s: float = 300.0) -> str | None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            resp = s3.head_object(Bucket=bucket, Key=key)
            status = resp.get("ReplicationStatus")
        except ClientError:
            status = None
        if status in terminal_statuses:
            return status
        time.sleep(2)
    raise AssertionError(f"replication status for {bucket}/{key} never reached {terminal_statuses} (last={status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
