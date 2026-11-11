"""package-version-history-retention-window."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "package-version-history-retention-window"
GROUP = "ordering"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetPackageVersionHistory gains one entry per UpdatePackage call; ordered by CreatedAt, the
    update CommitMessages appear in the order the updates were made."""
    client = ctx.client("opensearch")
    package_id, bucket, key = _create_package_with_source(ctx)

    # AWS publishes no fixed retention count, so this covers accumulation and order, not ageing out.
    commit_messages = ["sim2real-v2", "sim2real-v3", "sim2real-v4"]
    for message in commit_messages:
        client.update_package(
            PackageID=package_id,
            PackageSource={"S3BucketName": bucket, "S3Key": key},
            CommitMessage=message,
        )
        # Package APIs record CreatedAt at whole-second granularity; without a strictly
        # monotonic clock guarantee, keep updates distinguishable in time.
        time.sleep(1.5)

    history = client.get_package_version_history(PackageID=package_id)["PackageVersionHistoryList"]
    # PackageVersionHistoryList documents no order, so entries are ordered by their CreatedAt.
    ours = sorted((h for h in history if h.get("CommitMessage") in commit_messages), key=lambda h: h["CreatedAt"])
    seen_messages = [h.get("CommitMessage") for h in ours]
    assert len(seen_messages) == len(commit_messages), (
        f"expected all {len(commit_messages)} updates to appear in the version history, "
        f"got {seen_messages!r} out of {history!r}"
    )
    assert seen_messages == commit_messages, (
        f"expected CreatedAt ordering {commit_messages!r}, got {seen_messages!r}"
    )

def _create_package_with_source(ctx):
    """Create a real S3 bucket + object and a package backed by it. CreatePackage validates
    S3 accessibility synchronously, so a nonexistent bucket/key is rejected up front rather
    than accepted and only failing during the async COPYING stage.
    """
    s3 = ctx.client("s3")
    client = ctx.client("opensearch")
    bucket = ctx.unique_name("sim2real-pkgbucket-")
    key = "dictionary.txt"

    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "package-version-history-retention-window"}]}
    )
    s3.put_object(Bucket=bucket, Key=key, Body=b"sim2real\n")

    name = ctx.unique_name("sim2real-pkg-")
    resp = client.create_package(
        PackageName=name,
        PackageType="TXT-DICTIONARY",
        PackageSource={"S3BucketName": bucket, "S3Key": key},
    )
    package_id = resp["PackageDetails"]["PackageID"]
    ctx.on_cleanup(lambda: client.delete_package(PackageID=package_id))

    # Wait for the initial COPYING/VALIDATING pass to reach a terminal status before issuing
    # updates against it.
    deadline = time.monotonic() + 120
    status = None
    while time.monotonic() < deadline:
        status = client.describe_packages(
            Filters=[{"Name": "PackageID", "Value": [package_id]}]
        )["PackageDetailsList"][0]["PackageStatus"]
        if status not in ("COPYING", "VALIDATING"):
            break
        time.sleep(3)
    assert status == "AVAILABLE", f"package {package_id} did not become AVAILABLE: {status!r}"
    return package_id, bucket, key


def _delete_bucket(s3, bucket):
    try:
        objs = s3.list_object_versions(Bucket=bucket)
        to_delete = [{"Key": o["Key"], "VersionId": o["VersionId"]} for o in objs.get("Versions", [])]
        to_delete += [
            {"Key": o["Key"], "VersionId": o["VersionId"]} for o in objs.get("DeleteMarkers", [])
        ]
        if to_delete:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": to_delete}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        else:
            for o in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
