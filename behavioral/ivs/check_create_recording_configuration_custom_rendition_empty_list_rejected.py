"""create-recording-configuration-custom-rendition-empty-list-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-recording-configuration-custom-rendition-empty-list-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """renditionSelection=CUSTOM with an empty renditions list fails ValidationException with the exact message and
    creates nothing, while two configurations may point at the same S3 bucket."""
    ivs = ctx.client("ivs")
    bucket = _create_bucket(ctx)

    bad_name = ctx.unique_name("sim2real-ivs-rc-badrendition-")
    error = _client_error(
        lambda: ivs.create_recording_configuration(
            name=bad_name,
            destinationConfiguration={"s3": {"bucketName": bucket}},
            renditionConfiguration={"renditionSelection": "CUSTOM", "renditions": []},
        )
    )
    assert error["Code"] == "ValidationException", f"expected ValidationException, got {error!r}"
    assert error["Message"] == (
        "Request member: recordingConfiguration.renditionConfiguration failed to satisfy the "
        "constraints: recordingConfiguration.renditionConfiguration is invalid"
    ), f"unexpected validation message for an empty CUSTOM rendition list: {error['Message']!r}"

    found = [
        rc
        for rc in ivs.list_recording_configurations(maxResults=100)["recordingConfigurations"]
        if rc["name"] == bad_name
    ]
    assert found == [], f"a config from the rejected create exists: {found}"

    # Positive control #1: CUSTOM with a real rendition list is accepted.
    first = ivs.create_recording_configuration(
        name=ctx.unique_name("sim2real-ivs-rc-first-"),
        destinationConfiguration={"s3": {"bucketName": bucket}},
        renditionConfiguration={"renditionSelection": "CUSTOM", "renditions": ["HD"]},
    )["recordingConfiguration"]
    ctx.on_cleanup(lambda: ivs.delete_recording_configuration(arn=first["arn"]))
    assert first["renditionConfiguration"]["renditionSelection"] == "CUSTOM", first["renditionConfiguration"]
    assert first["renditionConfiguration"]["renditions"] == ["HD"], first["renditionConfiguration"]

    # Positive control #2: a second recording configuration is free to reuse the
    # same bucket as the first — no ConflictException on bucket reuse.
    second = ivs.create_recording_configuration(
        name=ctx.unique_name("sim2real-ivs-rc-second-"),
        destinationConfiguration={"s3": {"bucketName": bucket}},
    )["recordingConfiguration"]
    ctx.on_cleanup(lambda: ivs.delete_recording_configuration(arn=second["arn"]))
    assert second["arn"] != first["arn"], "second create returned the first config's arn"

    # Terminal read: independent GetRecordingConfiguration calls, not the create
    # responses, confirm both configurations persisted against the shared bucket.
    got_first = ivs.get_recording_configuration(arn=first["arn"])["recordingConfiguration"]
    got_second = ivs.get_recording_configuration(arn=second["arn"])["recordingConfiguration"]
    assert got_first["destinationConfiguration"]["s3"]["bucketName"] == bucket, got_first
    assert got_second["destinationConfiguration"]["s3"]["bucketName"] == bucket, got_second


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-ivs-rec-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    return bucket


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

