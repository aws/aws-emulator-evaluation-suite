"""recording-configuration-reaches-active-state."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "recording-configuration-reaches-active-state"
GROUP = "state"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRecordingConfiguration starts in CREATING and, for a valid same-account
    same-region S3 bucket, the async validation transitions it to ACTIVE."""
    ivs = ctx.client("ivs")
    bucket = _create_bucket(ctx)

    name = ctx.unique_name("sim2real-ivs-rc-")
    created = ivs.create_recording_configuration(
        name=name,
        destinationConfiguration={"s3": {"bucketName": bucket}},
        tags={"purpose": "sim2real"},
    )["recordingConfiguration"]
    arn = created["arn"]
    ctx.on_cleanup(lambda: ivs.delete_recording_configuration(arn=arn))

    assert created["state"] == "CREATING", f"expected CREATING immediately after create, got {created['state']}"

    final_state = _poll_until_terminal(ctx, arn)
    assert final_state == "ACTIVE", f"expected ACTIVE, recording configuration reached {final_state}"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-ivs-rec-")
    # us-east-1 is the one region where CreateBucketConfiguration must be omitted entirely;
    # every other region requires LocationConstraint to match ctx.region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "purpose", "Value": "sim2real"}]})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    return bucket


def _poll_until_terminal(ctx, arn: str, timeout_s: float = 90.0, interval_s: float = 3.0) -> str:
    ivs = ctx.client("ivs")
    deadline = time.monotonic() + timeout_s
    state = "CREATING"
    while time.monotonic() < deadline:
        state = ivs.get_recording_configuration(arn=arn)["recordingConfiguration"]["state"]
        if state != "CREATING":
            return state
        time.sleep(interval_s)
    raise AssertionError(f"recording configuration still CREATING after {timeout_s}s (never reached a terminal state)")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
