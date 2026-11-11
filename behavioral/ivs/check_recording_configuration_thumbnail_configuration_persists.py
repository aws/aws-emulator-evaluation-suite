"""recording-configuration-thumbnail-configuration-persists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "recording-configuration-thumbnail-configuration-persists"
GROUP = "state"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRecordingConfiguration persists thumbnailConfiguration and
    recordingReconnectWindowSeconds, and GetRecordingConfiguration reads them back unchanged."""
    ivs = ctx.client("ivs")
    bucket = _create_bucket(ctx)

    created = ivs.create_recording_configuration(
        name=ctx.unique_name("sim2real-ivs-thumb-"),
        destinationConfiguration={"s3": {"bucketName": bucket}},
        thumbnailConfiguration={
            "recordingMode": "INTERVAL",
            "targetIntervalSeconds": 30,
            "storage": ["LATEST"],
        },
        recordingReconnectWindowSeconds=60,
    )["recordingConfiguration"]
    arn = created["arn"]
    ctx.on_cleanup(lambda: ivs.delete_recording_configuration(arn=arn))

    assert created["thumbnailConfiguration"]["recordingMode"] == "INTERVAL", (
        f"expected recordingMode=INTERVAL in create response, got "
        f"{created['thumbnailConfiguration'].get('recordingMode')!r}"
    )
    assert created["thumbnailConfiguration"]["targetIntervalSeconds"] == 30, (
        f"expected targetIntervalSeconds=30 in create response, got "
        f"{created['thumbnailConfiguration'].get('targetIntervalSeconds')!r}"
    )
    assert created["thumbnailConfiguration"]["storage"] == ["LATEST"], (
        f"expected storage=['LATEST'] in create response, got "
        f"{created['thumbnailConfiguration'].get('storage')!r}"
    )
    assert created["recordingReconnectWindowSeconds"] == 60, (
        f"expected recordingReconnectWindowSeconds=60 in create response, got "
        f"{created.get('recordingReconnectWindowSeconds')!r}"
    )

    refetched = ivs.get_recording_configuration(arn=arn)["recordingConfiguration"]
    assert refetched["thumbnailConfiguration"]["recordingMode"] == "INTERVAL", (
        f"expected recordingMode=INTERVAL on refetch, got "
        f"{refetched['thumbnailConfiguration'].get('recordingMode')!r}"
    )
    assert refetched["thumbnailConfiguration"]["targetIntervalSeconds"] == 30, (
        f"expected targetIntervalSeconds=30 on refetch, got "
        f"{refetched['thumbnailConfiguration'].get('targetIntervalSeconds')!r}"
    )
    assert refetched["thumbnailConfiguration"]["storage"] == ["LATEST"], (
        f"expected storage=['LATEST'] on refetch, got "
        f"{refetched['thumbnailConfiguration'].get('storage')!r}"
    )
    assert refetched["recordingReconnectWindowSeconds"] == 60, (
        f"expected recordingReconnectWindowSeconds=60 on refetch, got "
        f"{refetched.get('recordingReconnectWindowSeconds')!r}"
    )


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-ivs-thumbb-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    return bucket


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
