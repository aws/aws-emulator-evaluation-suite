"""composition-auto-shutdown-without-publisher."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "composition-auto-shutdown-without-publisher"
GROUP = "state"
SERVICES = ["ivs-realtime"]


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
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


# timing:real-time — ttl: 60 s
@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """A Composition on a stage that never had a publisher auto-stops after the documented 60 s
    no-publisher idle window, timed from the moment the Composition starts."""
    ivs = ctx.client("ivs-realtime")
    bucket = _create_bucket(ctx)

    stage_arn = ivs.create_stage(
        name=ctx.unique_name("sim2real-stage-"), tags={"team": "sim2real"}
    )["stage"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_stage(arn=stage_arn))

    encoder_arn = ivs.create_encoder_configuration(
        name=ctx.unique_name("sim2real-enc-"), tags={"team": "sim2real"}
    )["encoderConfiguration"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_encoder_configuration(arn=encoder_arn))

    storage_arn = ivs.create_storage_configuration(
        name=ctx.unique_name("sim2real-storage-"),
        s3={"bucketName": bucket},
        tags={"team": "sim2real"},
    )["storageConfiguration"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_storage_configuration(arn=storage_arn))

    started = time.monotonic()
    comp_arn = ivs.start_composition(
        stageArn=stage_arn,
        destinations=[
            {
                "s3": {
                    "storageConfigurationArn": storage_arn,
                    "encoderConfigurationArns": [encoder_arn],
                }
            }
        ],
        tags={"team": "sim2real"},
    )["composition"]["arn"]

    final = _poll_until(
        lambda: ivs.get_composition(arn=comp_arn)["composition"],
        lambda c: c["state"] in ("STOPPED", "FAILED"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    elapsed = time.monotonic() - started
    assert final["state"] == "STOPPED", final["state"]
    assert final.get("endTime"), final
    # Docs promise auto-finalize at the 60s idle mark, timed from composition start.
    # A target that finalizes near-instantly (never honoring the idle window) or only
    # after a much longer stall (a different mechanism entirely) is not implementing
    # this rule -- it just happens to land on the same terminal state.
    assert 45.0 <= elapsed <= 150.0, (
        f"auto-shutdown observed after {elapsed:.1f}s; expected close to the "
        f"docs' ~60s no-publisher idle window"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
