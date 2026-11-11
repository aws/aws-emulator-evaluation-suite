"""s3-replication-role-trust-policy-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-replication-role-trust-policy-positive"
GROUP = "arn-resolution"
SERVICES = ["firehose", "kinesis", "s3"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role whose trust policy names s3.amazonaws.com replicates an object to the destination bucket with the same
    body, and the source object's replication status reaches COMPLETED."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    src = _create_bucket(ctx, s3, "sim2real-s3trust-src")
    dst = _create_bucket(ctx, s3, "sim2real-s3trust-dst")
    s3.put_bucket_versioning(Bucket=src, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_versioning(Bucket=dst, VersioningConfiguration={"Status": "Enabled"})

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetReplicationConfiguration",
                    "s3:ListBucket",
                    "s3:GetObjectVersionForReplication",
                    "s3:GetObjectVersionAcl",
                    "s3:GetObjectVersionTagging",
                ],
                "Resource": [f"arn:aws:s3:::{src}", f"arn:aws:s3:::{src}/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"],
                "Resource": f"arn:aws:s3:::{dst}/*",
            },
        ],
    }
    role_name = ctx.unique_name("sim2real-s3trust-role-")
    role_arn = _create_role(ctx, iam, role_name, "s3.amazonaws.com", policy_doc)

    replication_config = {
        "Role": role_arn,
        "Rules": [{
            "ID": "sim2real-repl-rule",
            "Status": "Enabled",
            "Priority": 1,
            "Filter": {},
            "DeleteMarkerReplication": {"Status": "Disabled"},
            "Destination": {"Bucket": f"arn:aws:s3:::{dst}"},
        }],
    }
    _put_replication_with_retry(s3, src, replication_config)
    ctx.on_cleanup(lambda: _delete_replication(s3, src))

    key = "sim2real/object.txt"
    body = f"replication-payload-{ctx.unique_name('marker-')}".encode()
    s3.put_object(Bucket=src, Key=key, Body=body)

    # Small objects without S3 Replication Time Control have no fixed SLA, but AWS docs
    # (userguide/replication-status.html) describe replication as completing in a short
    # window under normal conditions; poll generously rather than assert immediately.
    status = _poll_replication_status(s3, src, key, {"COMPLETED", "FAILED"}, timeout_s=300)
    assert status == "COMPLETED", f"expected COMPLETED replication status, got {status!r}"

    dest_contents = _poll_for_object(s3, dst, prefix=key, timeout_s=60)
    assert dest_contents, "replicated object never appeared in destination bucket"
    dest_body = s3.get_object(Bucket=dst, Key=key)["Body"].read()
    assert dest_body == body, f"expected replicated body {body!r}, got {dest_body!r}"


def _create_bucket(ctx: Any, s3, prefix: str) -> str:
    name = ctx.unique_name(f"{prefix}-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _empty_and_delete_bucket(s3, name: str) -> None:
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=name):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]}
                    for v in page.get("Versions", []) + page.get("DeleteMarkers", [])]
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


def _create_role(ctx: Any, iam, name: str, principal: str, policy_doc: dict) -> str:
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": principal},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    if policy_doc:
        iam.put_role_policy(RoleName=name, PolicyName=f"{name}-policy", PolicyDocument=json.dumps(policy_doc))
    return arn


def _delete_role(iam, name: str) -> None:
    try:
        for p in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=name, PolicyName=p)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _put_replication_with_retry(s3, bucket: str, config: dict, timeout_s: float = 30.0, interval_s: float = 5.0) -> None:
    """PutBucketReplication can transiently fail right after the role is created because
    S3 validates the role exists via IAM, which has not finished propagating yet."""
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            s3.put_bucket_replication(Bucket=bucket, ReplicationConfiguration=config)
            return
        except ClientError as e:
            last_err = e
            time.sleep(interval_s)
    assert last_err is not None, "timed out without ever attempting put_bucket_replication"
    raise last_err


def _delete_replication(s3, bucket: str) -> None:
    try:
        s3.delete_bucket_replication(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _poll_replication_status(s3, bucket: str, key: str, terminal: set[str], timeout_s: float = 300.0, interval_s: float = 10.0) -> str | None:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = s3.head_object(Bucket=bucket, Key=key)
        last_status = resp.get("ReplicationStatus")
        if last_status in terminal:
            return last_status
        time.sleep(interval_s)
    return last_status


def _poll_for_object(s3, bucket: str, prefix: str = "", timeout_s: float = 60.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
        contents = resp.get("Contents", [])
        if contents:
            return contents
        time.sleep(interval_s)
    return []


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
