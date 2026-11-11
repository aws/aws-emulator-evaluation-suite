"""s3-role-without-trust-policy-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "s3-role-without-trust-policy-rejected"
GROUP = "overly-permissive"
SERVICES = ["events", "firehose", "s3"]


@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutBucketReplication accepts a role that does not trust s3.amazonaws.com, but replication then
    reaches FAILED and the object never arrives; an identically-permissioned role that trusts S3
    replicates the object to COMPLETED."""
    s3 = ctx.client("s3")

    bad_src = _create_versioned_bucket(ctx, "sim2real-s3-src-bad-")
    bad_dst = _create_versioned_bucket(ctx, "sim2real-s3-dst-bad-")
    bad_role_arn = _create_role(ctx, "ec2.amazonaws.com", _replication_policy(bad_src, bad_dst))

    s3.put_bucket_replication(
        Bucket=bad_src,
        ReplicationConfiguration={"Role": bad_role_arn, "Rules": [_replication_rule(bad_dst)]},
    )
    # PutBucketReplication accepted the mistrusted role: the configuration is live.
    cfg = s3.get_bucket_replication(Bucket=bad_src)["ReplicationConfiguration"]
    assert cfg["Role"] == bad_role_arn, (
        f"PutBucketReplication with a mistrusted role should still be accepted as configuration"
        f" (expected Role={bad_role_arn}, GetBucketReplication reported Role={cfg['Role']!r})"
    )

    key = "sim2real-object.txt"
    marker = ctx.unique_name("sim2real-marker-")
    s3.put_object(Bucket=bad_src, Key=key, Body=marker.encode())

    status = _poll_replication_status(s3, bad_src, key, {"COMPLETED", "FAILED"}, timeout_s=180)
    assert status == "FAILED", (
        f"replication with a role that does not trust s3.amazonaws.com should terminally FAIL"
        f" (expected status=FAILED, head_object ReplicationStatus reported {status!r})"
    )

    dst_code, dst_message = _error(lambda: s3.get_object(Bucket=bad_dst, Key=key))
    assert dst_code == "NoSuchKey", (
        f"the object must never reach the destination bucket when replication FAILED"
        f" (expected GetObject error code=NoSuchKey, got {dst_code!r})"
    )
    assert dst_message == "The specified key does not exist.", (
        f"expected GetObject's NoSuchKey message 'The specified key does not exist.', got {dst_message!r}"
    )

    # positive control: an otherwise-identical, correctly-trusted role still replicates
    good_src = _create_versioned_bucket(ctx, "sim2real-s3-src-good-")
    good_dst = _create_versioned_bucket(ctx, "sim2real-s3-dst-good-")
    good_role_arn = _create_role(ctx, "s3.amazonaws.com", _replication_policy(good_src, good_dst))
    s3.put_bucket_replication(
        Bucket=good_src,
        ReplicationConfiguration={"Role": good_role_arn, "Rules": [_replication_rule(good_dst)]},
    )
    good_marker = ctx.unique_name("sim2real-marker-")
    s3.put_object(Bucket=good_src, Key=key, Body=good_marker.encode())
    good_status = _poll_replication_status(s3, good_src, key, {"COMPLETED", "FAILED"}, timeout_s=300)
    assert good_status == "COMPLETED", (
        f"the otherwise-identical role trusting s3.amazonaws.com must replicate successfully"
        f" (expected status=COMPLETED, head_object ReplicationStatus reported {good_status!r})"
    )
    replica = s3.get_object(Bucket=good_dst, Key=key)["Body"].read().decode()
    assert replica == good_marker, (
        f"the replicated object's bytes at the destination must match what was written at the"
        f" source (expected {good_marker!r}, destination GetObject returned {replica!r})"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn() and return the AWS error (Code, Message) it raised; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_versioned_bucket(ctx, prefix: str) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix)
    kwargs: dict[str, Any] = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
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


def _delete_role(iam, role_name: str, policy_name: str) -> None:
    """The inline policy has to go before the role; one cleanup keeps that order."""
    iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    iam.delete_role(RoleName=role_name)


def _create_role(ctx, trust_service: str, permissions: dict) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = resp["Role"]["Arn"]
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(permissions))
    ctx.on_cleanup(lambda: _delete_role(iam, role_name, policy_name))
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
