"""recording-configuration-active-state-transition."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "recording-configuration-active-state-transition"
GROUP = "state"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A RecordingConfiguration backed by a real, owned, same-region S3 bucket
    transitions CREATING -> ACTIVE (not CREATE_FAILED)."""
    ivs = ctx.client("ivs")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-ivs-rec-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        # S3 rejects an explicit LocationConstraint for us-east-1; every other region requires one.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "purpose", "Value": "sim2real"}]})

    resp = ivs.create_recording_configuration(
        name=ctx.unique_name("sim2real-ivs-reccfg-"),
        destinationConfiguration={"s3": {"bucketName": bucket}},
        tags={"purpose": "sim2real"},
    )
    cfg_arn = resp["recordingConfiguration"]["arn"]
    assert resp["recordingConfiguration"]["state"] == "CREATING", (
        f"expected CREATING immediately after create, got {resp['recordingConfiguration']['state']}"
    )

    def _cleanup_cfg():
        ivs.delete_recording_configuration(arn=cfg_arn)

    ctx.on_cleanup(_cleanup_cfg)

    final_state = _poll_until(
        lambda: ivs.get_recording_configuration(arn=cfg_arn)["recordingConfiguration"][
            "state"
        ],
        lambda state: state in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=90,
        interval_s=3,
        desc="recording configuration to leave CREATING",
    )
    assert final_state == "ACTIVE", f"expected ACTIVE, got {final_state}"

    cfg = ivs.get_recording_configuration(arn=cfg_arn)["recordingConfiguration"]
    assert cfg["destinationConfiguration"]["s3"]["bucketName"] == bucket, (
        f"expected destination bucket {bucket!r}, got "
        f"{cfg['destinationConfiguration']['s3']['bucketName']!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, desc="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}; last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
