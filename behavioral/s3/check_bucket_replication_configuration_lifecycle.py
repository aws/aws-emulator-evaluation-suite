"""bucket-replication-configuration-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bucket-replication-configuration-lifecycle"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutBucketReplication on a versioned bucket set -> Get reflects the rules;
    DeleteBucketReplication removes the configuration entirely."""
    s3 = ctx.client("s3")
    src = ctx.unique_name("sim2real-behav-repl-src-")
    dst = ctx.unique_name("sim2real-behav-repl-dst-")
    _create_bucket(ctx, s3, src)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, src))
    _create_bucket(ctx, s3, dst)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, dst))

    s3.put_bucket_versioning(Bucket=src, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_versioning(Bucket=dst, VersioningConfiguration={"Status": "Enabled"})

    role_arn = _create_replication_role(ctx, src, dst)

    dst_arn = f"arn:aws:s3:::{dst}"
    _put_replication_with_retry(
        lambda: s3.put_bucket_replication(
            Bucket=src,
            ReplicationConfiguration={
                "Role": role_arn,
                "Rules": [
                    {
                        "ID": "rule1",
                        "Status": "Enabled",
                        "Priority": 1,
                        "Filter": {"Prefix": ""},
                        "DeleteMarkerReplication": {"Status": "Disabled"},
                        "Destination": {"Bucket": dst_arn},
                    }
                ],
            },
        )
    )

    got = s3.get_bucket_replication(Bucket=src)
    rules = got["ReplicationConfiguration"]["Rules"]
    assert len(rules) == 1, rules
    assert rules[0]["Destination"]["Bucket"] == dst_arn, rules
    assert got["ReplicationConfiguration"]["Role"] == role_arn, got

    s3.delete_bucket_replication(Bucket=src)

    code, message = _error(lambda: s3.get_bucket_replication(Bucket=src))
    assert code == "ReplicationConfigurationNotFoundError", code
    assert message == "The replication configuration was not found", message


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_bucket(ctx, s3, name: str, **kwargs) -> None:
    params: dict = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)


def _empty_and_delete_bucket(s3, name: str, bypass_governance: bool = False) -> None:
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=name):
            to_delete = []
            for v in page.get("Versions", []):
                to_delete.append({"Key": v["Key"], "VersionId": v["VersionId"]})
            for m in page.get("DeleteMarkers", []):
                to_delete.append({"Key": m["Key"], "VersionId": m["VersionId"]})
            if to_delete:
                kwargs = {"Bucket": name, "Delete": {"Objects": to_delete}}
                if bypass_governance:
                    kwargs["BypassGovernanceRetention"] = True
                failed = s3.delete_objects(**kwargs).get("Errors")
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


def _create_replication_role(ctx, src: str, dst: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-repl-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "s3.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetReplicationConfiguration", "s3:ListBucket"],
                "Resource": f"arn:aws:s3:::{src}",
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObjectVersionForReplication", "s3:GetObjectVersionAcl", "s3:GetObjectVersionTagging"],
                "Resource": f"arn:aws:s3:::{src}/*",
            },
            {
                "Effect": "Allow",
                "Action": ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"],
                "Resource": f"arn:aws:s3:::{dst}/*",
            },
        ],
    }
    policy_name = "replication-policy"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: _delete_role_policy(iam, role_name, policy_name))

    return role_arn


def _put_replication_with_retry(fn, *, timeout_s: float = 60.0, interval_s: float = 3.0) -> None:
    """IAM role propagation to S3's replication engine can lag a few seconds behind role
    creation; retry the PutBucketReplication call in a bounded loop instead of a fixed sleep,
    re-raising the last error if it never succeeds within the deadline."""
    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            fn()
            return
        except ClientError as exc:
            last_error = exc
            time.sleep(interval_s)
    raise AssertionError(f"PutBucketReplication never accepted the replication role within {timeout_s}s: {last_error}")


def _delete_role_policy(iam, role_name: str, policy_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
