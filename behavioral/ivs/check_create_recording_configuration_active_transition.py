"""create-recording-configuration-active-transition."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-recording-configuration-active-transition"
GROUP = "state"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRecordingConfiguration starts in state CREATING and transitions to ACTIVE once the
    S3 destination bucket is validated by the IVS service-linked role."""
    ivs = ctx.client("ivs")
    bucket = _create_recording_bucket(ctx)
    name = ctx.unique_name("sim2real-ivs-rec-")
    resp = ivs.create_recording_configuration(
        name=name,
        destinationConfiguration={"s3": {"bucketName": bucket}},
        tags={"purpose": "sim2real"},
    )
    arn = resp["recordingConfiguration"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_recording_configuration(arn=arn))
    initial_state = resp["recordingConfiguration"]["state"]
    assert initial_state == "CREATING", f"expected initial state CREATING, got {initial_state}"

    state = _poll_recording_configuration_state(ctx, arn, {"ACTIVE", "CREATE_FAILED"}, timeout_s=90)
    assert state == "ACTIVE", f"expected terminal state ACTIVE, got {state}"


def _create_recording_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-ivs-rec-").lower()
    # S3 rejects an explicit LocationConstraint for us-east-1 (its bucket-creation default);
    # every other region requires one naming itself.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "purpose", "Value": "sim2real"}]})
    ctx.on_cleanup(lambda: _safe_delete_bucket(s3, bucket))
    return bucket


def _safe_delete_bucket(s3, bucket) -> None:
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _poll_recording_configuration_state(ctx, arn, terminal_states, timeout_s=90.0, interval_s=3.0):
    ivs = ctx.client("ivs")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = ivs.get_recording_configuration(arn=arn)["recordingConfiguration"]["state"]
        if state in terminal_states:
            return state
        time.sleep(interval_s)
    raise AssertionError(f"recording configuration never reached a terminal state (last: {state})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
