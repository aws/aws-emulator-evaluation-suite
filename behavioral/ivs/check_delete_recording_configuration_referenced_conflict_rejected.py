"""delete-recording-configuration-referenced-conflict-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-recording-configuration-referenced-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteRecordingConfiguration on a configuration a channel references fails ConflictException with the exact
    message and it survives; after the channel is deleted it deletes, then Get and a repeat delete fail not-found."""
    ivs = ctx.client("ivs")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-ivs-refconflict-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        # S3 CreateBucket rejects an explicit LocationConstraint of us-east-1 itself.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    cfg_arn = ivs.create_recording_configuration(
        name=ctx.unique_name("sim2real-ivs-refconflict-cfg-"),
        destinationConfiguration={"s3": {"bucketName": bucket}},
        tags={"purpose": "sim2real"},
    )["recordingConfiguration"]["arn"]

    state = _poll_until(
        lambda: ivs.get_recording_configuration(arn=cfg_arn)["recordingConfiguration"][
            "state"
        ],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=90,
        interval_s=3,
    )
    assert state == "ACTIVE", f"expected recording configuration to reach ACTIVE, got {state!r}"

    channel_arn = ivs.create_channel(
        name=ctx.unique_name("sim2real-ivs-refconflict-chan-"),
        recordingConfigurationArn=cfg_arn,
        tags={"purpose": "sim2real"},
    )["channel"]["arn"]

    cfg_deleted = {"done": False}
    channel_deleted = {"done": False}

    def _cleanup_cfg():
        if not cfg_deleted["done"]:
            ivs.delete_recording_configuration(arn=cfg_arn)

    def _cleanup_channel():
        if not channel_deleted["done"]:
            ivs.delete_channel(arn=channel_arn)

    ctx.on_cleanup(_cleanup_cfg)
    ctx.on_cleanup(_cleanup_channel)

    error = _client_error(lambda: ivs.delete_recording_configuration(arn=cfg_arn))
    assert error["Code"] == "ConflictException", f"expected ConflictException, got {error!r}"
    assert error["Message"] == (
        f"Unable to perform ivs:DeleteRecordingConfiguration while {cfg_arn} "
        f"is still attached to a channel"
    ), f"unexpected DeleteRecordingConfiguration conflict message: {error['Message']!r}"

    still_there = ivs.get_recording_configuration(arn=cfg_arn)["recordingConfiguration"]
    assert still_there["arn"] == cfg_arn, (
        f"expected the rejected delete to leave {cfg_arn} in place, got {still_there!r}"
    )

    ivs.delete_channel(arn=channel_arn)
    channel_deleted["done"] = True

    ivs.delete_recording_configuration(arn=cfg_arn)
    cfg_deleted["done"] = True

    error_after = _client_error(lambda: ivs.get_recording_configuration(arn=cfg_arn))
    assert error_after["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {error_after!r}"
    )
    assert error_after["Message"] == f"Resource: {cfg_arn} not found", (
        f"unexpected GetRecordingConfiguration not-found message: {error_after['Message']!r}"
    )

    delete_again = _client_error(lambda: ivs.delete_recording_configuration(arn=cfg_arn))
    assert delete_again["Code"] == "ResourceNotFoundException", (
        f"expected a repeat delete of the dead arn to fail not-found, got {delete_again!r}"
    )
    assert delete_again["Message"] == f"Resource: {cfg_arn} not found", (
        f"unexpected DeleteRecordingConfiguration not-found message: {delete_again['Message']!r}"
    )


def _client_error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
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
