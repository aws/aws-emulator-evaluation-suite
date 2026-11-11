"""stop-composition-terminal-state-conflict-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-composition-terminal-state-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs-realtime"]


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopComposition on an already-STOPPED composition is rejected with ConflictException."""
    ivs = ctx.client("ivs-realtime")
    bucket = _create_bucket(ctx)

    stage_arn = ivs.create_stage(
        name=ctx.unique_name("sim2real-stage-"), tags={"sim2real": CHECK}
    )["stage"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_stage(arn=stage_arn))
    encoder_arn = ivs.create_encoder_configuration(
        name=ctx.unique_name("sim2real-enc-"), tags={"sim2real": CHECK}
    )["encoderConfiguration"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_encoder_configuration(arn=encoder_arn))
    storage_arn = ivs.create_storage_configuration(
        name=ctx.unique_name("sim2real-storage-"),
        s3={"bucketName": bucket},
        tags={"sim2real": CHECK},
    )["storageConfiguration"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_storage_configuration(arn=storage_arn))

    comp_arn = ivs.start_composition(
        stageArn=stage_arn,
        destinations=[
            {"s3": {"storageConfigurationArn": storage_arn, "encoderConfigurationArns": [encoder_arn]}}
        ],
    )["composition"]["arn"]

    _poll_until(
        lambda: ivs.get_composition(arn=comp_arn)["composition"],
        lambda c: c["state"] == "ACTIVE",
        timeout_s=60.0,
    )

    # Positive control: the first StopComposition call succeeds.
    ivs.stop_composition(arn=comp_arn)
    stopped = _poll_until(
        lambda: ivs.get_composition(arn=comp_arn)["composition"],
        lambda c: c["state"] in ("STOPPED", "FAILED"),
        timeout_s=60.0,
    )
    assert stopped["state"] == "STOPPED", stopped["state"]
    end_time_after_first_stop = stopped["endTime"]

    # Calling StopComposition again on the now-terminal composition must be rejected.
    code, message = _error(lambda: ivs.stop_composition(arn=comp_arn))
    assert code == "ConflictException", code
    assert message == f"Resource: {comp_arn} is in a transitioning state", message

    # The effect is absent: endTime is unchanged, state is still STOPPED (not re-stopped/mutated).
    unchanged = ivs.get_composition(arn=comp_arn)["composition"]
    assert unchanged["state"] == "STOPPED", unchanged["state"]
    assert unchanged["endTime"] == end_time_after_first_stop, (unchanged["endTime"], end_time_after_first_stop)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
