"""recording-configuration-thumbnail-and-rendition-persisted."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "recording-configuration-thumbnail-and-rendition-persisted"
GROUP = "state"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """thumbnailConfiguration, renditionConfiguration, and recordingReconnectWindowSeconds
    set at creation are persisted verbatim and readable via GetRecordingConfiguration
    once the configuration reaches ACTIVE."""
    ivs = ctx.client("ivs")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-ivs-recfields-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    resp = ivs.create_recording_configuration(
        name=ctx.unique_name("sim2real-ivs-recfields-cfg-"),
        destinationConfiguration={"s3": {"bucketName": bucket}},
        thumbnailConfiguration={
            "recordingMode": "INTERVAL",
            "targetIntervalSeconds": 30,
            "storage": ["SEQUENTIAL"],
        },
        renditionConfiguration={"renditionSelection": "ALL"},
        recordingReconnectWindowSeconds=60,
        tags={"purpose": "sim2real"},
    )
    cfg_arn = resp["recordingConfiguration"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_recording_configuration(arn=cfg_arn))

    state = _poll_until(
        lambda: ivs.get_recording_configuration(arn=cfg_arn)["recordingConfiguration"][
            "state"
        ],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=90,
        interval_s=3,
    )
    assert state == "ACTIVE", f"expected recording configuration to reach ACTIVE, got {state}"

    cfg = ivs.get_recording_configuration(arn=cfg_arn)["recordingConfiguration"]
    assert cfg["thumbnailConfiguration"]["recordingMode"] == "INTERVAL", cfg["thumbnailConfiguration"]
    assert cfg["thumbnailConfiguration"]["targetIntervalSeconds"] == 30, cfg["thumbnailConfiguration"]
    assert cfg["thumbnailConfiguration"]["storage"] == ["SEQUENTIAL"], cfg["thumbnailConfiguration"]
    assert cfg["renditionConfiguration"]["renditionSelection"] == "ALL", cfg["renditionConfiguration"]
    assert cfg["recordingReconnectWindowSeconds"] == 60, cfg["recordingReconnectWindowSeconds"]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for predicate; last value: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
