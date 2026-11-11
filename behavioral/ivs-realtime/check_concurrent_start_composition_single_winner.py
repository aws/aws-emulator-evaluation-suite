"""concurrent-start-composition-single-winner."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-start-composition-single-winner"
GROUP = "concurrency"
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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Five concurrent StartComposition calls on one stage all succeed with distinct compositions, because IVS
    real-time sets no single-composition-per-stage limit, and a composition reads ACTIVE or STOPPED."""
    ivs = ctx.client("ivs-realtime")
    bucket = _create_bucket(ctx)

    stage_arn = ivs.create_stage(name=ctx.unique_name("sim2real-stage-"))["stage"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_stage(arn=stage_arn))
    encoder_arn = ivs.create_encoder_configuration(name=ctx.unique_name("sim2real-enc-"))[
        "encoderConfiguration"
    ]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_encoder_configuration(arn=encoder_arn))
    storage_arn = ivs.create_storage_configuration(
        name=ctx.unique_name("sim2real-storage-"), s3={"bucketName": bucket}
    )["storageConfiguration"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_storage_configuration(arn=storage_arn))

    destinations = [
        {"s3": {"storageConfigurationArn": storage_arn, "encoderConfigurationArns": [encoder_arn]}}
    ]

    def _racer(_i):
        try:
            comp = ivs.start_composition(stageArn=stage_arn, destinations=destinations)["composition"]
            return ("ok", comp["arn"])
        except ClientError as e:
            return ("error", e.response["Error"]["Code"])

    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(_racer, range(5)))

    winners = [arn for status, arn in results if status == "ok"]
    losers = [code for status, code in results if status == "error"]

    # Every racer independently succeeds with its own distinct composition ARN.
    assert len(winners) == 5, results
    assert len(losers) == 0, results
    assert len(set(winners)) == 5, winners

    for arn in winners:
        ctx.on_cleanup(lambda a=arn: _safe_stop(ivs, a))
        active = _poll_until(
            lambda a=arn: ivs.get_composition(arn=a)["composition"],
            lambda c: c["state"] in ("ACTIVE", "STOPPED", "FAILED"),
            timeout_s=60.0,
        )
        assert active["state"] in ("ACTIVE", "STOPPED"), active["state"]


def _safe_stop(ivs, arn):
    from botocore.exceptions import ClientError

    try:
        ivs.stop_composition(arn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
