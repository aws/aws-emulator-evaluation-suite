"""serverless-cache-snapshot-full-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "serverless-cache-snapshot-full-lifecycle"
GROUP = "state-machine"
SERVICES = ["elasticache"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A serverless cache snapshot moves creating -> available -> exported (back to available) ->
    deleting -> gone across Create/Describe/Export/DeleteServerlessCacheSnapshot."""
    ec = ctx.client("elasticache")
    s3 = ctx.client("s3")

    bucket_name = ctx.unique_name("sim2real-ec-export-")
    _create_export_bucket(ctx, s3, bucket_name)

    cache_name = ctx.unique_name("sim2real-slc-")
    ec.create_serverless_cache(
        ServerlessCacheName=cache_name,
        Engine="redis",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        SubnetIds=ctx.network().subnet_ids[:3],
    )
    ctx.on_cleanup(lambda: _delete_serverless_cache_tolerant(ec, cache_name))
    status = _wait_for_serverless_cache_status(ec, cache_name, "available", timeout_s=1500)
    assert status == "available"

    snapshot_name = ctx.unique_name("sim2real-slcsnap-")
    ec.create_serverless_cache_snapshot(
        ServerlessCacheSnapshotName=snapshot_name,
        ServerlessCacheName=cache_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_serverless_snapshot_tolerant(ec, snapshot_name))
    status = _wait_for_serverless_snapshot_status(ec, snapshot_name, "available", timeout_s=600)
    assert status == "available"

    ec.export_serverless_cache_snapshot(
        ServerlessCacheSnapshotName=snapshot_name, S3BucketName=bucket_name
    )
    # export is transient ("exporting"); the terminal state on success is "available" again
    final_status = _wait_for_serverless_snapshot_status(
        ec, snapshot_name, "available", timeout_s=900
    )
    assert final_status == "available"

    objects = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
    assert len(objects) >= 1, "export did not place any object in the target S3 bucket"

    ec.delete_serverless_cache_snapshot(ServerlessCacheSnapshotName=snapshot_name)
    _wait_for_serverless_snapshot_gone(ec, snapshot_name, timeout_s=300)

    try:
        ec.delete_serverless_cache_snapshot(ServerlessCacheSnapshotName=snapshot_name)
        raise AssertionError("re-deleting an already-deleted serverless cache snapshot succeeded")
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message")
        assert code == "ServerlessCacheSnapshotNotFoundFault", (
            f"expected ServerlessCacheSnapshotNotFoundFault on re-delete, got {code}"
        )
        assert message == "Serverless cache snapshot with specified name does not exists.", (
            f"expected the exact re-delete NotFound message, got {message!r}"
        )


def _create_export_bucket(ctx, s3, bucket_name: str) -> None:
    region = ctx.region
    # S3 CreateBucket quirk, not a region pin: us-east-1 rejects an explicit
    # LocationConstraint of its own region, every other region requires one.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
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


def _delete_serverless_cache_tolerant(ec, name: str) -> None:
    try:
        ec.delete_serverless_cache(ServerlessCacheName=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ServerlessCacheNotFoundFault":
            raise


def _delete_serverless_snapshot_tolerant(ec, name: str) -> None:
    try:
        ec.delete_serverless_cache_snapshot(ServerlessCacheSnapshotName=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ServerlessCacheSnapshotNotFoundFault":
            raise


def _wait_for_serverless_cache_status(
    ec, name: str, target: str, timeout_s: float = 900.0, interval_s: float = 15.0
) -> str:
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


def _wait_for_serverless_snapshot_status(
    ec, name: str, target: str, timeout_s: float = 600.0, interval_s: float = 15.0
) -> str:
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
    raise AssertionError(
        f"serverless cache snapshot {name} never reached {target!r}, last saw {last!r}"
    )


def _wait_for_serverless_snapshot_gone(
    ec, name: str, timeout_s: float = 300.0, interval_s: float = 10.0
) -> None:
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
    raise AssertionError(f"serverless cache snapshot {name} was not deleted within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
