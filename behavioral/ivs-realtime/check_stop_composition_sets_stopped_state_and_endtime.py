"""stop-composition-sets-stopped-state-and-endtime."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "stop-composition-sets-stopped-state-and-endtime"
GROUP = "state"
SERVICES = ["ivs-realtime"]


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-ivsrt-").lower()
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StopComposition transitions an ACTIVE composition to STOPPED and stamps endTime."""
    ivs = ctx.client("ivs-realtime")
    bucket = _create_bucket(ctx)

    stage_arn = ivs.create_stage(
        name=ctx.unique_name("sim2real-stage-"), tags={"env": "sim2real", "owner": "behavioral"}
    )["stage"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_stage(arn=stage_arn))

    encoder_arn = ivs.create_encoder_configuration(
        name=ctx.unique_name("sim2real-enc-"), tags={"env": "sim2real", "owner": "behavioral"}
    )["encoderConfiguration"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_encoder_configuration(arn=encoder_arn))

    storage_arn = ivs.create_storage_configuration(
        name=ctx.unique_name("sim2real-storage-"),
        s3={"bucketName": bucket},
        tags={"env": "sim2real", "owner": "behavioral"},
    )["storageConfiguration"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_storage_configuration(arn=storage_arn))

    composition = ivs.start_composition(
        stageArn=stage_arn,
        destinations=[
            {
                "s3": {
                    "storageConfigurationArn": storage_arn,
                    "encoderConfigurationArns": [encoder_arn],
                }
            }
        ],
    )["composition"]
    comp_arn = composition["arn"]
    assert composition["state"] in ("STARTING", "ACTIVE"), composition["state"]

    active = _poll_until(
        lambda: ivs.get_composition(arn=comp_arn)["composition"],
        lambda c: c["state"] in ("ACTIVE", "STOPPED", "FAILED"),
        timeout_s=60.0,
    )
    assert active["state"] == "ACTIVE", active["state"]
    assert not active.get("endTime"), f"expected no endTime while ACTIVE, got {active.get('endTime')!r}"

    ivs.stop_composition(arn=comp_arn)

    stopped = _poll_until(
        lambda: ivs.get_composition(arn=comp_arn)["composition"],
        lambda c: c["state"] in ("STOPPED", "FAILED"),
        timeout_s=60.0,
    )
    assert stopped["state"] == "STOPPED", stopped["state"]
    assert stopped.get("endTime"), stopped


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
