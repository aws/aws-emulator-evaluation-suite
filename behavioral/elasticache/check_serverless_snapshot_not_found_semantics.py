"""serverless-snapshot-not-found-semantics."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code

def _error(fn):
    """Call fn(), which must raise a ClientError; return its (Error.Code, Error.Message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected a ClientError but the call SUCCEEDED")

def _assert_error(fn, expected):
    """Assert fn() fails with the (code, message) pair `expected`: the code Fault/Exception-suffix
    normalized, the message exact; return the code."""
    code, actual = _error(fn)
    assert _fault_base(code) == _fault_base(expected[0]), f"expected {expected[0]}, got {code} ({actual!r})"
    assert actual == expected[1], f"{expected[0]}: expected message {expected[1]!r}, got {actual!r}"
    return code

CHECK = "serverless-snapshot-not-found-semantics"
GROUP = 'serverless'
SERVICES = ['elasticache']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A real serverless snapshot describes, exports an object to S3 and copies; Describe, Copy, Export and Delete of
    an unknown snapshot, and Delete of the deleted real one, fail with ServerlessCacheSnapshotNotFound and their
    exact messages."""
    ec = ctx.client("elasticache")
    s3 = ctx.client("s3")

    bucket_name = ctx.unique_name("sim2real-escs-nf-export-")
    _create_export_bucket(ctx, s3, bucket_name)

    cache_name = ctx.unique_name("sim2real-escs-nf-cache-")
    ec.create_serverless_cache(ServerlessCacheName=cache_name, Engine="redis", SubnetIds=ctx.network().subnet_ids[:3])
    ctx.on_cleanup(lambda: _delete_cache_tolerant(ec, cache_name))
    _wait_cache_status(ec, cache_name, "available", timeout_s=1500)

    real_name = ctx.unique_name("sim2real-escs-nf-real-")
    ec.create_serverless_cache_snapshot(
        ServerlessCacheSnapshotName=real_name, ServerlessCacheName=cache_name,
    )
    _wait_snapshot_status(ec, real_name, "available", timeout_s=600)

    # --- positive control: describe finds the real snapshot ---
    found = ec.describe_serverless_cache_snapshots(
        ServerlessCacheSnapshotName=real_name,
    )["ServerlessCacheSnapshots"]
    assert found and found[0]["ServerlessCacheSnapshotName"] == real_name, (
        f"expected describe to find {real_name}, got {found}"
    )

    # --- positive control: export succeeds against the real snapshot ---
    ec.export_serverless_cache_snapshot(
        ServerlessCacheSnapshotName=real_name, S3BucketName=bucket_name,
    )
    _wait_snapshot_status(ec, real_name, "available", timeout_s=900)
    objects = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
    assert len(objects) >= 1, "export accepted but placed no object in the target bucket"

    # --- positive control: copy succeeds against the real snapshot ---
    copy_name = ctx.unique_name("sim2real-escs-nf-copy-")
    ec.copy_serverless_cache_snapshot(
        SourceServerlessCacheSnapshotName=real_name,
        TargetServerlessCacheSnapshotName=copy_name,
    )
    ctx.on_cleanup(lambda: _delete_snapshot_tolerant(ec, copy_name))
    _wait_snapshot_status(ec, copy_name, "available", timeout_s=600)
    copy_found = ec.describe_serverless_cache_snapshots(
        ServerlessCacheSnapshotName=copy_name,
    )["ServerlessCacheSnapshots"]
    assert copy_found and copy_found[0]["ServerlessCacheSnapshotName"] == copy_name, (
        f"expected the copy to produce a describable snapshot {copy_name}, got {copy_found}"
    )

    # --- the not-found contract: the same four operations, a name that never existed ---
    bogus = ctx.unique_name("sim2real-behav-escs-missing-")
    _assert_error(
        lambda: ec.describe_serverless_cache_snapshots(
            ServerlessCacheSnapshotName=bogus,
        ),
        ("ServerlessCacheSnapshotNotFoundFault",
        f"Serverless Cache Snapshot with name {bogus} not found"),
    )
    _assert_error(
        lambda: ec.copy_serverless_cache_snapshot(
            SourceServerlessCacheSnapshotName=bogus,
            TargetServerlessCacheSnapshotName=ctx.unique_name("sim2real-behav-escs-dst-"),
        ),
        ("ServerlessCacheSnapshotNotFoundFault",
        "Source serverless cache snapshot does not exist."),
    )
    _assert_error(
        lambda: ec.export_serverless_cache_snapshot(
            ServerlessCacheSnapshotName=bogus,
            S3BucketName=bucket_name,
        ),
        ("ServerlessCacheSnapshotNotFoundFault",
        "Serverless cache snapshot with specified name does not exists."),
    )
    _assert_error(
        lambda: ec.delete_serverless_cache_snapshot(
            ServerlessCacheSnapshotName=bogus,
        ),
        ("ServerlessCacheSnapshotNotFoundFault",
        "Serverless cache snapshot with specified name does not exists."),
    )

    # --- delete: positive control on the real snapshot, then prove gone, then prove it stays gone ---
    ec.delete_serverless_cache_snapshot(ServerlessCacheSnapshotName=real_name)
    _wait_snapshot_gone(ec, real_name, timeout_s=300)
    _assert_error(
        lambda: ec.delete_serverless_cache_snapshot(ServerlessCacheSnapshotName=real_name),
        ("ServerlessCacheSnapshotNotFoundFault",
        "Serverless cache snapshot with specified name does not exists."),
    )


def _create_export_bucket(ctx, s3, bucket_name: str) -> None:
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region},
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ElastiCacheSnapshotExport",
                "Effect": "Allow",
                "Principal": {"Service": f"{region}.elasticache-snapshot.amazonaws.com"},
                "Action": [
                    "s3:PutObject",
                    "s3:GetObject",
                    "s3:ListBucket",
                    "s3:GetBucketAcl",
                    "s3:ListMultipartUploadParts",
                    "s3:ListBucketMultipartUploads",
                ],
                "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))

def _empty_and_delete_bucket(s3, bucket_name: str) -> None:
    try:
        objects = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
        for obj in objects:
            s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise

def _delete_cache_tolerant(ec, name: str) -> None:
    try:
        ec.delete_serverless_cache(ServerlessCacheName=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ServerlessCacheNotFoundFault":
            raise

def _delete_snapshot_tolerant(ec, name: str) -> None:
    try:
        ec.delete_serverless_cache_snapshot(ServerlessCacheSnapshotName=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ServerlessCacheSnapshotNotFoundFault":
            raise

def _wait_cache_status(ec, name: str, target: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = ec.describe_serverless_caches(ServerlessCacheName=name)
        caches = resp.get("ServerlessCaches", [])
        if caches:
            last = caches[0]["Status"]
            if last == target:
                return last
        time.sleep(interval_s)
    raise AssertionError(f"serverless cache {name} never reached {target!r}, last saw {last!r}")

def _wait_snapshot_status(ec, name: str, target: str, timeout_s: float = 600.0, interval_s: float = 15.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = ec.describe_serverless_cache_snapshots(ServerlessCacheSnapshotName=name)
        snaps = resp.get("ServerlessCacheSnapshots", [])
        if snaps:
            last = snaps[0]["Status"]
            if last == target:
                return last
        time.sleep(interval_s)
    raise AssertionError(f"serverless snapshot {name} never reached {target!r}, last saw {last!r}")

def _wait_snapshot_gone(ec, name: str, timeout_s: float = 300.0, interval_s: float = 10.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = ec.describe_serverless_cache_snapshots(ServerlessCacheSnapshotName=name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ServerlessCacheSnapshotNotFoundFault":
                return
            raise
        if not resp.get("ServerlessCacheSnapshots"):
            return
        time.sleep(interval_s)
    raise AssertionError(f"serverless snapshot {name} was not deleted within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
