"""bucket-replication-config-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "bucket-replication-config-lifecycle"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Cross-bucket replication configuration round-trips through put/get exactly (role ARN and
    per-rule destination), and DeleteBucketReplication reverts the source bucket to having no
    replication configuration."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    source = ctx.unique_name("sim2real-repl-src-")
    dest = ctx.unique_name("sim2real-repl-dst-")
    _create_bucket(ctx, s3, source)
    _create_bucket(ctx, s3, dest)
    s3.put_bucket_versioning(Bucket=source, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_versioning(Bucket=dest, VersioningConfiguration={"Status": "Enabled"})

    role_arn = _create_replication_role(ctx, iam, source, dest)

    dest_arn = f"arn:aws:s3:::{dest}"
    replication_config = {
        "Role": role_arn,
        "Rules": [
            {
                "ID": "rule1",
                "Status": "Enabled",
                "Priority": 1,
                "Filter": {"Prefix": ""},
                "DeleteMarkerReplication": {"Status": "Disabled"},
                "Destination": {"Bucket": dest_arn},
            }
        ],
    }
    # PutBucketReplication can transiently reject a just-created role while IAM's
    # eventual-consistency propagates it to S3's control plane -- poll to the condition
    # (the call actually succeeding) in a bounded loop instead of a fixed sleep.
    _poll_until_put_succeeds(
        ctx,
        lambda: s3.put_bucket_replication(Bucket=source, ReplicationConfiguration=replication_config),
        timeout_s=60.0,
        interval_s=3.0,
    )

    got = s3.get_bucket_replication(Bucket=source)["ReplicationConfiguration"]
    assert got["Role"] == role_arn, f"expected Role {role_arn!r}, got {got.get('Role')!r}"
    assert len(got["Rules"]) == 1, f"expected exactly 1 rule, got {got['Rules']!r}"
    rule = got["Rules"][0]
    assert rule["ID"] == "rule1", f"expected rule ID 'rule1' to round-trip, got {rule.get('ID')!r}"
    assert rule["Status"] == "Enabled", f"expected rule Status 'Enabled', got {rule.get('Status')!r}"
    assert rule["Destination"]["Bucket"] == dest_arn, (
        f"expected Destination.Bucket {dest_arn!r}, got {rule.get('Destination')!r}"
    )

    s3.delete_bucket_replication(Bucket=source)
    code, message = _error(lambda: s3.get_bucket_replication(Bucket=source))
    assert code == "ReplicationConfigurationNotFoundError", code
    assert message == "The replication configuration was not found", message


def _create_bucket(ctx, s3, name, **kwargs):
    params = {"Bucket": name}
    if getattr(ctx, "region", None) and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, s3, name))


def _empty_and_delete_bucket(ctx, s3, name):
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            objs += [{"Key": d["Key"], "VersionId": d["VersionId"]} for d in page.get("DeleteMarkers", [])]
            if objs:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        for u in s3.list_multipart_uploads(Bucket=name).get("Uploads", []):
            s3.abort_multipart_upload(Bucket=name, Key=u["Key"], UploadId=u["UploadId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_replication_role(ctx, iam, source_bucket, dest_bucket):
    role_name = ctx.unique_name("sim2real-repl-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "s3.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "replication-policy"
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
                "Resource": [f"arn:aws:s3:::{dest_bucket}/*"],
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(permission_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses is never read as a code mismatch."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until_put_succeeds(ctx, fn, *, timeout_s=60.0, interval_s=3.0):
    """Retry fn() in a bounded loop until it stops raising (used where the failure is a
    transient IAM-role-propagation ClientError), re-raising the last error if it never
    succeeds within the timeout."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            fn()
            return
        except ClientError as e:
            last_error = e
            time.sleep(interval_s)
    raise AssertionError(f"operation never succeeded within {timeout_s}s: {last_error}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
