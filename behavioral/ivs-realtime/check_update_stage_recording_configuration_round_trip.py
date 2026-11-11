"""update-stage-recording-configuration-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-stage-recording-configuration-round-trip"
GROUP = "state"
SERVICES = ["ivs-realtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateStage attaches an autoParticipantRecordingConfiguration with a real storage configuration ARN, which
    GetStage reflects, and storageConfigurationArn="" resets it to empty."""
    client = ctx.client("ivs-realtime")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-ivsrt-rec-").lower().replace("_", "-")
    create_kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})

    storage_arn = client.create_storage_configuration(
        name=ctx.unique_name("sim2real-storage"),
        s3={"bucketName": bucket},
        tags={"sim2real": "true"},
    )["storageConfiguration"]["arn"]
    ctx.on_cleanup(lambda: client.delete_storage_configuration(arn=storage_arn))

    stage_arn = client.create_stage(
        name=ctx.unique_name("sim2real-stage"), tags={"sim2real": "true"}
    )["stage"]["arn"]
    ctx.on_cleanup(lambda: client.delete_stage(arn=stage_arn))

    updated = client.update_stage(
        arn=stage_arn,
        autoParticipantRecordingConfiguration={"storageConfigurationArn": storage_arn},
    )["stage"]
    assert updated["autoParticipantRecordingConfiguration"]["storageConfigurationArn"] == storage_arn, (
        f"expected update_stage response to echo {storage_arn!r}, got "
        f"{updated.get('autoParticipantRecordingConfiguration')!r}"
    )

    fetched = client.get_stage(arn=stage_arn)["stage"]
    assert fetched["autoParticipantRecordingConfiguration"]["storageConfigurationArn"] == storage_arn, (
        f"expected get_stage to reflect {storage_arn!r}, got "
        f"{fetched.get('autoParticipantRecordingConfiguration')!r}"
    )

    reset = client.update_stage(
        arn=stage_arn,
        autoParticipantRecordingConfiguration={"storageConfigurationArn": ""},
    )["stage"]
    assert reset["autoParticipantRecordingConfiguration"]["storageConfigurationArn"] == "", (
        f"expected update_stage reset response to clear storageConfigurationArn, got "
        f"{reset.get('autoParticipantRecordingConfiguration')!r}"
    )

    # The terminal assertion must be an independent read at the destination, not the
    # mutating call's own echoed response.
    refetched = client.get_stage(arn=stage_arn)["stage"]
    assert refetched["autoParticipantRecordingConfiguration"]["storageConfigurationArn"] == "", (
        f"expected get_stage after reset to show no storage configuration, got "
        f"{refetched.get('autoParticipantRecordingConfiguration')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
