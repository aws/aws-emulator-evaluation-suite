"""recording-configuration-rendition-selection-persists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "recording-configuration-rendition-selection-persists"
GROUP = "state"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRecordingConfiguration persists a CUSTOM renditionConfiguration (a specific
    subset of renditions), and GetRecordingConfiguration reads back the same subset --
    not ALL renditions and not an empty list."""
    ivs = ctx.client("ivs")
    bucket = _create_bucket(ctx)

    created = ivs.create_recording_configuration(
        name=ctx.unique_name("sim2real-ivs-rendition-"),
        destinationConfiguration={"s3": {"bucketName": bucket}},
        renditionConfiguration={
            "renditionSelection": "CUSTOM",
            "renditions": ["HD", "SD"],
        },
        tags={"purpose": "sim2real"},
    )["recordingConfiguration"]
    arn = created["arn"]
    ctx.on_cleanup(lambda: ivs.delete_recording_configuration(arn=arn))

    assert created["renditionConfiguration"]["renditionSelection"] == "CUSTOM", (
        f"expected renditionSelection CUSTOM on create response, "
        f"got {created['renditionConfiguration']['renditionSelection']!r}"
    )
    assert sorted(created["renditionConfiguration"]["renditions"]) == ["HD", "SD"], (
        f"expected renditions ['HD', 'SD'] on create response, "
        f"got {sorted(created['renditionConfiguration']['renditions'])!r}"
    )

    refetched = ivs.get_recording_configuration(arn=arn)["recordingConfiguration"]
    assert refetched["renditionConfiguration"]["renditionSelection"] == "CUSTOM", (
        f"expected renditionSelection CUSTOM on independent GetRecordingConfiguration, "
        f"got {refetched['renditionConfiguration']['renditionSelection']!r}"
    )
    assert sorted(refetched["renditionConfiguration"]["renditions"]) == ["HD", "SD"], (
        f"expected renditions ['HD', 'SD'] on independent GetRecordingConfiguration, "
        f"got {sorted(refetched['renditionConfiguration']['renditions'])!r}"
    )
    # It must be exactly the requested subset, not every available rendition.
    assert "FULL_HD" not in refetched["renditionConfiguration"]["renditions"], (
        f"CUSTOM subset must not be widened to include FULL_HD, "
        f"got {refetched['renditionConfiguration']['renditions']!r}"
    )
    assert "LOWEST_RESOLUTION" not in refetched["renditionConfiguration"]["renditions"], (
        f"CUSTOM subset must not be widened to include LOWEST_RESOLUTION, "
        f"got {refetched['renditionConfiguration']['renditions']!r}"
    )


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-ivs-rendb-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        # S3 rejects an explicit LocationConstraint for us-east-1; every other region requires one.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "purpose", "Value": "sim2real"}]})
    return bucket


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
