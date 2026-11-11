"""update-channel-disables-recording-with-empty-arn."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-channel-disables-recording-with-empty-arn"
GROUP = "state"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateChannel with recordingConfigurationArn="" detaches an active recording
    configuration from a channel, per:
    https://docs.aws.amazon.com/ivs/latest/LowLatencyUserGuide/create-channel-auto-r2s3.html
    ('How to Disable Recording')."""
    ivs = ctx.client("ivs")
    bucket = _create_bucket(ctx)
    rc_arn = ivs.create_recording_configuration(
        name=ctx.unique_name("sim2real-ivs-disable-rc-"),
        destinationConfiguration={"s3": {"bucketName": bucket}},
        tags={"purpose": "sim2real"},
    )["recordingConfiguration"]["arn"]
    active_rc = _poll_until(
        probe=lambda: ivs.get_recording_configuration(arn=rc_arn)["recordingConfiguration"],
        predicate=lambda r: r["state"] != "CREATING",
        timeout_s=90.0,
        interval_s=3.0,
    )
    ctx.on_cleanup(lambda: ivs.delete_recording_configuration(arn=rc_arn))
    assert active_rc["state"] == "ACTIVE", f"expected ACTIVE, got {active_rc['state']!r}"

    channel = ivs.create_channel(
        name=ctx.unique_name("sim2real-ivs-disable-chan-"),
        recordingConfigurationArn=rc_arn,
        tags={"purpose": "sim2real"},
    )["channel"]
    channel_arn = channel["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=channel_arn))
    assert channel["recordingConfigurationArn"] == rc_arn, (
        f"expected channel to echo {rc_arn!r} at creation, got "
        f"{channel['recordingConfigurationArn']!r}"
    )

    updated = ivs.update_channel(arn=channel_arn, recordingConfigurationArn="")["channel"]
    assert updated["recordingConfigurationArn"] == "", (
        f"expected UpdateChannel's own response to echo the detach, got "
        f"{updated['recordingConfigurationArn']!r}"
    )

    refetched = ivs.get_channel(arn=channel_arn)["channel"]
    assert refetched["recordingConfigurationArn"] == "", (
        f"expected GetChannel (independent read) to show the detach, got "
        f"{refetched['recordingConfigurationArn']!r}"
    )

    # The recording configuration resource itself is unaffected by detaching it: it
    # stays ACTIVE and reachable by its own arn, it is just no longer referenced.
    still_active = ivs.get_recording_configuration(arn=rc_arn)["recordingConfiguration"]
    assert still_active["arn"] == rc_arn, (
        f"expected the recording configuration to remain reachable at {rc_arn!r}, "
        f"got {still_active['arn']!r}"
    )
    assert still_active["state"] == "ACTIVE", (
        f"expected detaching the channel to leave the recording configuration ACTIVE, "
        f"got {still_active['state']!r}"
    )


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-ivs-disableb-").lower().replace("_", "-")
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
