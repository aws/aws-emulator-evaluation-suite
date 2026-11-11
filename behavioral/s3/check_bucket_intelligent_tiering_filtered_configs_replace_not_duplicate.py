"""bucket-intelligent-tiering-filtered-configs-replace-not-duplicate."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bucket-intelligent-tiering-filtered-configs-replace-not-duplicate"
GROUP = "intelligent-tiering-config"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two Intelligent-Tiering configs keep independent filters and tierings through List/Get, a
    re-Put of the same Id replaces that entry rather than duplicating it, and no object is created.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    unfiltered = {
        "Id": "EntireBucket", "Status": "Enabled",
        "Tierings": [{"Days": 90, "AccessTier": "ARCHIVE_ACCESS"}],
    }
    filtered = {
        "Id": "Filtered",
        "Filter": {"And": {"Prefix": "logs/", "Tags": [{"Key": "env", "Value": "prod"}]}},
        "Status": "Disabled",
        "Tierings": [
            {"Days": 90, "AccessTier": "ARCHIVE_ACCESS"},
            {"Days": 180, "AccessTier": "DEEP_ARCHIVE_ACCESS"},
        ],
    }
    s3.put_bucket_intelligent_tiering_configuration(
        Bucket=bucket, Id="EntireBucket", IntelligentTieringConfiguration=unfiltered
    )
    s3.put_bucket_intelligent_tiering_configuration(
        Bucket=bucket, Id="Filtered", IntelligentTieringConfiguration=filtered
    )

    listed = s3.list_bucket_intelligent_tiering_configurations(Bucket=bucket)
    by_id = {c["Id"]: c for c in listed["IntelligentTieringConfigurationList"]}
    assert set(by_id) == {"EntireBucket", "Filtered"}, (
        f"expected exactly the two configs just created, got {sorted(by_id)!r}"
    )
    assert "Filter" not in by_id["EntireBucket"], (
        f"EntireBucket was created with no Filter and must list with none, got "
        f"{by_id['EntireBucket'].get('Filter')!r}"
    )
    assert by_id["Filtered"]["Filter"] == filtered["Filter"], (
        f"Filtered's And{{Prefix,Tags}} filter did not round-trip: {by_id['Filtered'].get('Filter')!r}"
    )
    assert by_id["Filtered"]["Status"] == "Disabled" and len(by_id["Filtered"]["Tierings"]) == 2, (
        f"Filtered's Status/Tierings did not round-trip: {by_id['Filtered']!r}"
    )
    assert by_id["EntireBucket"]["Status"] == "Enabled" and len(by_id["EntireBucket"]["Tierings"]) == 1, (
        f"EntireBucket's Status/Tierings did not round-trip: {by_id['EntireBucket']!r}"
    )

    replacement = {
        "Id": "EntireBucket", "Status": "Disabled",
        "Tierings": [{"Days": 180, "AccessTier": "DEEP_ARCHIVE_ACCESS"}],
    }
    s3.put_bucket_intelligent_tiering_configuration(
        Bucket=bucket, Id="EntireBucket", IntelligentTieringConfiguration=replacement
    )
    got = s3.get_bucket_intelligent_tiering_configuration(Bucket=bucket, Id="EntireBucket")
    cfg = got["IntelligentTieringConfiguration"]
    assert cfg["Status"] == "Disabled" and cfg["Tierings"] == replacement["Tierings"], (
        f"GetBucketIntelligentTieringConfiguration after replace returned {cfg!r}, expected the "
        f"REPLACEMENT body {replacement!r}"
    )

    listed_after = s3.list_bucket_intelligent_tiering_configurations(Bucket=bucket)
    ids_after = [c["Id"] for c in listed_after["IntelligentTieringConfigurationList"]]
    assert sorted(ids_after) == ["EntireBucket", "Filtered"], (
        f"replacing EntireBucket must not duplicate it; expected exactly 2 configs, got {ids_after!r}"
    )
    by_id_after = {c["Id"]: c for c in listed_after["IntelligentTieringConfigurationList"]}
    assert by_id_after["Filtered"]["Filter"] == filtered["Filter"], (
        "replacing EntireBucket must leave the unrelated Filtered config untouched, but its "
        f"Filter is now {by_id_after['Filtered'].get('Filter')!r}"
    )

    objects = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
    assert objects == [], (
        f"Intelligent-Tiering config calls must never create objects, but ListObjectsV2 found "
        f"{objects!r}"
    )

    s3.delete_bucket_intelligent_tiering_configuration(Bucket=bucket, Id="EntireBucket")
    s3.delete_bucket_intelligent_tiering_configuration(Bucket=bucket, Id="Filtered")
    final = s3.list_bucket_intelligent_tiering_configurations(Bucket=bucket)
    assert final.get("IntelligentTieringConfigurationList", []) == [], (
        f"expected no configs after deleting both, got {final.get('IntelligentTieringConfigurationList')!r}"
    )


def _delete_bucket(client, bucket):
    """Delete every object version and delete marker, then the bucket; raise unless already gone."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise RuntimeError(f"could not empty {bucket}: {exc}") from exc
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise RuntimeError(f"could not delete bucket {bucket}: {exc}") from exc


def _new_bucket(ctx, s3):
    name = ctx.unique_name("sim2real-behav-tier-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
