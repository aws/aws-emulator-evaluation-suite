"""bucket-logging-roundtrip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bucket-logging-roundtrip"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A fresh bucket starts with logging disabled (GetBucketLogging returns no
    LoggingEnabled block); PutBucketLogging enables a target bucket/prefix and
    GetBucketLogging reflects the new state."""
    s3 = ctx.client("s3")
    src = ctx.unique_name("sim2real-behav-log-src-")
    target = ctx.unique_name("sim2real-behav-log-tgt-")
    _create_bucket(ctx, s3, src)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, src))
    _create_bucket(ctx, s3, target)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, target))

    initial = s3.get_bucket_logging(Bucket=src)
    assert "LoggingEnabled" not in initial, initial

    # Allow ACL usage on the target bucket, and grant the S3 log delivery group the
    # permissions it needs to write access logs there.
    s3.put_bucket_ownership_controls(
        Bucket=target, OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]}
    )
    owner = s3.get_bucket_acl(Bucket=target)["Owner"]
    s3.put_bucket_acl(
        Bucket=target,
        AccessControlPolicy={
            "Owner": owner,
            "Grants": [
                {"Grantee": {"Type": "CanonicalUser", "ID": owner["ID"]}, "Permission": "FULL_CONTROL"},
                {
                    "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery"},
                    "Permission": "WRITE",
                },
                {
                    "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery"},
                    "Permission": "READ_ACP",
                },
            ],
        },
    )

    prefix = "access-logs/"
    s3.put_bucket_logging(
        Bucket=src,
        BucketLoggingStatus={
            "LoggingEnabled": {"TargetBucket": target, "TargetPrefix": prefix}
        },
    )

    got = s3.get_bucket_logging(Bucket=src)
    enabled = got["LoggingEnabled"]
    assert enabled["TargetBucket"] == target, enabled
    assert enabled["TargetPrefix"] == prefix, enabled


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
