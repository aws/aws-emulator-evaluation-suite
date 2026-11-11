"""delete-recording-configuration-referenced-by-channel-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-recording-configuration-referenced-by-channel-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A recording configuration still referenced by a channel cannot be deleted; once the
    channel stops referencing it, deletion succeeds."""
    ivs = ctx.client("ivs")
    bucket = _create_bucket(ctx)
    rc = ivs.create_recording_configuration(
        name=ctx.unique_name("sim2real-ivs-refrc-"),
        destinationConfiguration={"s3": {"bucketName": bucket}},
        tags={"purpose": "sim2real"},
    )["recordingConfiguration"]
    rc_arn = rc["arn"]
    _poll_until(
        probe=lambda: ivs.get_recording_configuration(arn=rc_arn)["recordingConfiguration"],
        predicate=lambda r: r["state"] != "CREATING",
        timeout_s=90.0,
        interval_s=3.0,
    )

    channel = ivs.create_channel(
        name=ctx.unique_name("sim2real-ivs-refchan-"),
        recordingConfigurationArn=rc_arn,
        tags={"purpose": "sim2real"},
    )["channel"]
    channel_arn = channel["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=channel_arn))
    assert channel["recordingConfigurationArn"] == rc_arn, (
        f"expected channel to echo back the recording config it was created with, "
        f"got {channel['recordingConfigurationArn']!r}"
    )

    error = _client_error(lambda: ivs.delete_recording_configuration(arn=rc_arn))
    assert error["Code"] == "ConflictException", f"expected ConflictException, got {error!r}"
    assert error["Message"] == (
        f"Unable to perform ivs:DeleteRecordingConfiguration while {rc_arn} "
        f"is still attached to a channel"
    ), f"unexpected DeleteRecordingConfiguration conflict message: {error['Message']!r}"

    # The recording configuration must still exist, untouched, after the rejected delete.
    still_there = ivs.get_recording_configuration(arn=rc_arn)["recordingConfiguration"]
    assert still_there["arn"] == rc_arn, (
        f"recording config should survive a rejected delete, got arn={still_there['arn']!r}"
    )

    # Positive control: once the channel no longer references it, deletion succeeds.
    ivs.update_channel(arn=channel_arn, recordingConfigurationArn="")
    ivs.delete_recording_configuration(arn=rc_arn)

    error_after = _client_error(lambda: ivs.get_recording_configuration(arn=rc_arn))
    assert error_after["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {error_after!r}"
    )
    assert error_after["Message"] == f"Resource: {rc_arn} not found", (
        f"unexpected GetRecordingConfiguration not-found message: {error_after['Message']!r}"
    )

    # A mutation on the now-dead id must also fail, not resurrect or no-op silently.
    second_delete = _client_error(lambda: ivs.delete_recording_configuration(arn=rc_arn))
    assert second_delete["Code"] == "ResourceNotFoundException", (
        f"expected a second delete on a gone recording config to fail "
        f"ResourceNotFoundException, got {second_delete!r}"
    )
    assert second_delete["Message"] == f"Resource: {rc_arn} not found", (
        f"unexpected DeleteRecordingConfiguration not-found message: {second_delete['Message']!r}"
    )


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-ivs-refb-").lower().replace("_", "-")
    # us-east-1 is a genuine S3 API quirk: CreateBucketConfiguration.LocationConstraint
    # must be omitted there and supplied everywhere else.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    return bucket


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
