"""bucket-intelligent-tiering-archive-tier-minimum-days-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bucket-intelligent-tiering-archive-tier-minimum-days-rejected"
GROUP = "intelligent-tiering-config"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ARCHIVE_ACCESS below 90 days and DEEP_ARCHIVE_ACCESS below 180 are rejected InvalidAccessTier
    and never stored, a floor tighter than the model's Days range; 90-day ARCHIVE is accepted.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    bad = {
        "Id": "TooSoon", "Status": "Enabled",
        "Tierings": [{"Days": 30, "AccessTier": "ARCHIVE_ACCESS"}],
    }
    code, message = _rejection(lambda: s3.put_bucket_intelligent_tiering_configuration(
        Bucket=bucket, Id="TooSoon", IntelligentTieringConfiguration=bad
    ))
    assert code == "InvalidAccessTier", (
        f"expected InvalidAccessTier for an ARCHIVE_ACCESS tiering of 30 days, got {code!r}"
    )
    assert message == "Days specified in ARCHIVE_ACCESS tier should not be less than 90.", (
        f"InvalidAccessTier for ARCHIVE_ACCESS at 30 days must carry S3's own message; got {message!r}"
    )

    missing, missing_message = _rejection(lambda: s3.get_bucket_intelligent_tiering_configuration(
        Bucket=bucket, Id="TooSoon"
    ))
    assert missing == "NoSuchConfiguration", (
        f"the rejected config must not exist; GetBucketIntelligentTieringConfiguration returned "
        f"{missing!r} instead of NoSuchConfiguration"
    )
    assert missing_message == "The specified configuration does not exist.", (
        f"NoSuchConfiguration must carry S3's own message; got {missing_message!r}"
    )
    listed = s3.list_bucket_intelligent_tiering_configurations(Bucket=bucket)
    assert listed.get("IntelligentTieringConfigurationList", []) == [], (
        f"the rejected config must not be listed, got {listed.get('IntelligentTieringConfigurationList')!r}"
    )

    good = {
        "Id": "AtFloor", "Status": "Enabled",
        "Tierings": [{"Days": 90, "AccessTier": "ARCHIVE_ACCESS"}],
    }
    s3.put_bucket_intelligent_tiering_configuration(
        Bucket=bucket, Id="AtFloor", IntelligentTieringConfiguration=good
    )
    ctx.on_cleanup(lambda: s3.delete_bucket_intelligent_tiering_configuration(Bucket=bucket, Id="AtFloor"))
    got = s3.get_bucket_intelligent_tiering_configuration(Bucket=bucket, Id="AtFloor")
    cfg = got["IntelligentTieringConfiguration"]
    assert cfg["Tierings"] == good["Tierings"], (
        f"the 90-day control config did not round-trip: {cfg!r}"
    )

    bad_deep = {
        "Id": "DeepTooSoon", "Status": "Enabled",
        "Tierings": [{"Days": 90, "AccessTier": "DEEP_ARCHIVE_ACCESS"}],
    }
    deep_code, deep_message = _rejection(lambda: s3.put_bucket_intelligent_tiering_configuration(
        Bucket=bucket, Id="DeepTooSoon", IntelligentTieringConfiguration=bad_deep
    ))
    assert deep_code == "InvalidAccessTier", (
        f"expected InvalidAccessTier for a DEEP_ARCHIVE_ACCESS tiering of 90 days, got {deep_code!r}"
    )
    assert deep_message == "Days specified in DEEP_ARCHIVE_ACCESS tier should not be less than 180.", (
        f"InvalidAccessTier for DEEP_ARCHIVE_ACCESS at 90 days must carry S3's own message; got "
        f"{deep_message!r}"
    )


def _delete_bucket(client, bucket):
    """Delete every version and delete marker, then the bucket; raise on any failure but
    NoSuchBucket."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3):
    name = ctx.unique_name("sim2real-behav-tiermin-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _rejection(fn) -> tuple[str, str]:
    """(code, message) of the AWS error fn() raises; raises itself when the call SUCCEEDS."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"the call succeeded where real AWS rejects it; it returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
