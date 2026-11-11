"""s3-role-missing-trust-relationship-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "s3-role-missing-trust-relationship-negative"
GROUP = "overly-permissive"
SERVICES = ["firehose", "kinesis", "s3"]


@tags("axis:negative-delivery", "cap:c4", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """With a replication role that does not trust s3.amazonaws.com the object's replication status reaches FAILED and
    the destination stays empty, while a role that trusts S3 replicates the same body (COMPLETED)."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    # --- broken pair: role trusts ec2.amazonaws.com instead of s3.amazonaws.com ---
    bad_src = _create_bucket(ctx, s3, "sim2real-s3notrust-bad-src")
    bad_dst = _create_bucket(ctx, s3, "sim2real-s3notrust-bad-dst")
    s3.put_bucket_versioning(Bucket=bad_src, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_versioning(Bucket=bad_dst, VersioningConfiguration={"Status": "Enabled"})

    repl_policy = _replication_policy(bad_src, bad_dst)
    bad_role_name = ctx.unique_name("sim2real-s3notrust-bad-role-")
    bad_role_arn = _create_role(ctx, iam, bad_role_name, "ec2.amazonaws.com", repl_policy)

    _put_replication_with_retry(s3, bad_src, _replication_config(bad_role_arn, bad_dst))
    ctx.on_cleanup(lambda: _delete_replication(s3, bad_src))

    key = "sim2real/object.txt"
    s3.put_object(Bucket=bad_src, Key=key, Body=b"should-never-replicate")

    # AWS docs (userguide/replication-status.html): objects transition to FAILED for
    # issues such as missing replication role permissions -- an unassumable role is
    # exactly that case. Poll generously rather than assert immediately.
    status = _poll_replication_status(s3, bad_src, key, {"COMPLETED", "FAILED"}, timeout_s=300)
    assert status == "FAILED", f"expected FAILED replication status, got {status!r}"
    assert s3.list_objects_v2(Bucket=bad_dst).get("Contents", []) == [], (
        "object must never have reached the destination bucket"
    )

    # --- positive control: same shape, role correctly trusts s3.amazonaws.com ---
    good_src = _create_bucket(ctx, s3, "sim2real-s3notrust-good-src")
    good_dst = _create_bucket(ctx, s3, "sim2real-s3notrust-good-dst")
    s3.put_bucket_versioning(Bucket=good_src, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_versioning(Bucket=good_dst, VersioningConfiguration={"Status": "Enabled"})

    good_role_name = ctx.unique_name("sim2real-s3notrust-good-role-")
    good_role_arn = _create_role(
        ctx, iam, good_role_name, "s3.amazonaws.com", _replication_policy(good_src, good_dst)
    )
    _put_replication_with_retry(s3, good_src, _replication_config(good_role_arn, good_dst))
    ctx.on_cleanup(lambda: _delete_replication(s3, good_src))

    body = b"should-replicate-fine"
    s3.put_object(Bucket=good_src, Key=key, Body=body)
    good_status = _poll_replication_status(s3, good_src, key, {"COMPLETED", "FAILED"}, timeout_s=300)
    assert good_status == "COMPLETED", f"positive control: expected COMPLETED, got {good_status!r}"
    dest_contents = _poll_for_object(s3, good_dst, prefix=key, timeout_s=60)
    assert dest_contents, "positive control: replicated object never appeared in destination bucket"
    dest_body = s3.get_object(Bucket=good_dst, Key=key)["Body"].read()
    assert dest_body == body, f"positive control: replica body {dest_body!r} != source body {body!r}"


def _replication_policy(src: str, dst: str) -> dict:
    return {
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


def _replication_config(role_arn: str, dst: str) -> dict:
    return {
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


def _create_bucket(ctx: Any, s3, prefix: str) -> str:
    name = ctx.unique_name(f"{prefix}-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]})
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
        Tags=[{"Key": "simparity-check", "Value": CHECK}],
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
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            s3.put_bucket_replication(Bucket=bucket, ReplicationConfiguration=config)
            return
        except ClientError as e:
            last_err = e
            time.sleep(interval_s)
    assert last_err is not None, "retry loop exited without ever calling put_bucket_replication"
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
