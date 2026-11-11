"""create-file-system-unknown-role-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-file-system-unknown-role-not-found"
GROUP = "error-semantics"
SERVICES = ["s3files"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFileSystem referencing a well-formed but nonexistent IAM role ARN is accepted synchronously
    (the role isn't dereferenced until provisioning), then the file system asynchronously transitions to
    'error' status rather than 'available'."""
    s3files = ctx.client("s3files")
    bucket = _create_versioned_bucket(ctx)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-s3files-ghost-role-')}"

    resp = s3files.create_file_system(
        bucket=bucket["arn"],
        roleArn=bogus_role_arn,
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    fs_id = resp["fileSystemId"]
    ctx.on_cleanup(lambda: _safe_ignore_not_found(lambda: s3files.delete_file_system(fileSystemId=fs_id, forceDelete=True)))

    # On real AWS the statusMessage naming the access-denied role appears while still 'creating'
    # well inside 180s, but the terminal flip to 'error' itself takes over five minutes; this
    # ceiling carries headroom over that.
    final = _poll_until(
        lambda: s3files.get_file_system(fileSystemId=fs_id),
        lambda r: r.get("status") in ("available", "error"),
        timeout_s=900.0,
        interval_s=10.0,
    )
    assert final["status"] == "error", (
        f"expected a nonexistent role to drive the file system to 'error' status, got {final['status']!r}"
    )
    assert final.get("statusMessage"), "expected a statusMessage explaining the role validation failure"


# ===== helpers (self-contained) =====

def _safe_ignore_not_found(fn):
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_versioned_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-s3files-")
    kwargs = {"Bucket": name}
    # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint;
    # every other region requires one. Not a pin to us-east-1 — ctx.region drives the bucket.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})

    def _cleanup():
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=name):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])]
            if objs:
                s3.delete_objects(Bucket=name, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return {"name": name, "arn": f"arn:aws:s3:::{name}"}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
