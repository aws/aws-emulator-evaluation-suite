"""s3-replication-role-missing-trust-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "s3-replication-role-missing-trust-negative"
GROUP = "overly-permissive"
SERVICES = ["cloudformation", "dynamodb", "s3"]


@tags(
    "axis:negative-delivery",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "dp:api",
    "plane:data",
)
def run(ctx: Any) -> None:
    """PutBucketReplication accepts a role trusting ec2.amazonaws.com instead of s3.amazonaws.com, but
    an object written to the source bucket is never replicated; the same setup with an
    s3.amazonaws.com-trusted role replicates the object with its body intact."""
    s3 = ctx.client("s3")

    # --- negative: role trusts the wrong service principal ---
    bad_source = ctx.unique_name("sim2real-s3repltrust-badsrc-")
    bad_dest = ctx.unique_name("sim2real-s3repltrust-baddst-")
    _create_versioned_bucket(ctx, bad_source)
    _create_versioned_bucket(ctx, bad_dest)
    bad_role_arn = _create_replication_role(
        ctx, bad_source, bad_dest, trust_service="ec2.amazonaws.com", name_hint="s3repltrust-badrole"
    )
    _put_replication_config(ctx, bad_source, bad_role_arn, bad_dest)

    # --- positive control: identical setup, role correctly trusts s3.amazonaws.com ---
    good_source = ctx.unique_name("sim2real-s3repltrust-goodsrc-")
    good_dest = ctx.unique_name("sim2real-s3repltrust-gooddst-")
    _create_versioned_bucket(ctx, good_source)
    _create_versioned_bucket(ctx, good_dest)
    good_role_arn = _create_replication_role(
        ctx, good_source, good_dest, trust_service="s3.amazonaws.com", name_hint="s3repltrust-goodrole"
    )
    _put_replication_config(ctx, good_source, good_role_arn, good_dest)

    # The negative object is written first, so by the time the control replicates it has waited
    # at least as long; the hold after that is scaled to the control's own replication latency.
    bad_key = "replicated/should-not-appear.txt"
    s3.put_object(Bucket=bad_source, Key=bad_key, Body=b"must not replicate")
    good_key = "replicated/should-appear.txt"
    good_body = b"must replicate"
    started = time.monotonic()
    s3.put_object(Bucket=good_source, Key=good_key, Body=good_body)
    replica = _wait_for_replica(ctx, good_dest, good_key, timeout_s=300)
    assert replica == good_body, "control replication object body mismatch"
    latency_s = time.monotonic() - started
    _assert_never_replicates(ctx, bad_dest, bad_key, timeout_s=max(30.0, 2.0 * latency_s))


def _create_versioned_bucket(ctx: Any, name: str) -> str:
    s3 = ctx.client("s3")
    kwargs: dict = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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


def _create_replication_role(ctx: Any, source_bucket: str, dest_bucket: str, trust_service: str, name_hint: str) -> str:
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name(f"sim2real-{name_hint}-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
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


def _put_replication_config(ctx: Any, source_bucket: str, role_arn: str, dest_bucket: str) -> None:
    s3 = ctx.client("s3")
    s3.put_bucket_replication(
        Bucket=source_bucket,
        ReplicationConfiguration={
            "Role": role_arn,
            "Rules": [
                {
                    "ID": "sim2real-replicate-all",
                    "Status": "Enabled",
                    "Priority": 1,
                    "Filter": {"Prefix": ""},
                    "DeleteMarkerReplication": {"Status": "Disabled"},
                    "Destination": {"Bucket": f"arn:aws:s3:::{dest_bucket}"},
                }
            ],
        },
    )


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


def _assert_never_replicates(ctx: Any, bucket: str, key: str, timeout_s: float = 120.0, interval_s: float = 5.0) -> None:
    from botocore.exceptions import ClientError

    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            s3.get_object(Bucket=bucket, Key=key)
        except ClientError as e:
            if e.response["Error"]["Code"] in ("NoSuchKey", "404"):
                time.sleep(interval_s)
                continue
            raise
        else:
            raise AssertionError(
                f"object {key!r} replicated into {bucket!r} despite the role's trust "
                "policy not permitting s3.amazonaws.com to assume it"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
