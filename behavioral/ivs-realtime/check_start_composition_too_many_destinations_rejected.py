"""start-composition-too-many-destinations-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "start-composition-too-many-destinations-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs-realtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartComposition with 3 destinations fails ValidationException with the exact maximum-length-2 message and
    creates nothing, while one valid destination on the same wiring reaches ACTIVE."""
    ivsrt = ctx.client("ivs-realtime")
    bucket = _create_bucket(ctx)

    stage = ivsrt.create_stage(
        name=ctx.unique_name("sim2real-ivsrt-stage-"), tags={"env": "sim2real", "owner": "behavioral"}
    )["stage"]
    ctx.on_cleanup(lambda: ivsrt.delete_stage(arn=stage["arn"]))

    encoder_arn = ivsrt.create_encoder_configuration(
        name=ctx.unique_name("sim2real-enc-"), tags={"env": "sim2real", "owner": "behavioral"}
    )["encoderConfiguration"]["arn"]
    ctx.on_cleanup(lambda: ivsrt.delete_encoder_configuration(arn=encoder_arn))

    storage_arn = ivsrt.create_storage_configuration(
        name=ctx.unique_name("sim2real-storage-"),
        s3={"bucketName": bucket},
        tags={"env": "sim2real", "owner": "behavioral"},
    )["storageConfiguration"]["arn"]
    ctx.on_cleanup(lambda: ivsrt.delete_storage_configuration(arn=storage_arn))

    def _dest(name):
        return {
            "name": name,
            "s3": {"storageConfigurationArn": storage_arn, "encoderConfigurationArns": [encoder_arn]},
        }

    # Positive control: a single valid destination on this exact stage/encoder/storage
    # wiring succeeds and reaches ACTIVE.
    comp_arn = ivsrt.start_composition(stageArn=stage["arn"], destinations=[_dest("dest-0")])[
        "composition"
    ]["arn"]
    active = _poll_until(
        lambda: ivsrt.get_composition(arn=comp_arn)["composition"],
        lambda c: c["state"] in ("ACTIVE", "FAILED", "STOPPED"),
        timeout_s=60.0,
    )
    assert active["state"] == "ACTIVE", active["state"]
    ivsrt.stop_composition(arn=comp_arn)
    _poll_until(
        lambda: ivsrt.get_composition(arn=comp_arn)["composition"],
        lambda c: c["state"] in ("STOPPED", "FAILED"),
        timeout_s=60.0,
    )

    before = {c["arn"] for c in ivsrt.list_compositions(filterByStageArn=stage["arn"])["compositions"]}

    code, message = _error(
        lambda: ivsrt.start_composition(
            stageArn=stage["arn"],
            destinations=[_dest("dest-1"), _dest("dest-2"), _dest("dest-3")],
        )
    )
    assert code == "ValidationException", code
    assert message == "StartComposition.destinations is required to have a maximum length of 2, found 3", message

    # Effect absent: the rejected call created no new composition for this stage.
    after = {c["arn"] for c in ivsrt.list_compositions(filterByStageArn=stage["arn"])["compositions"]}
    assert after == before, (before, after)

    # The stage itself is still fully functional.
    assert ivsrt.get_stage(arn=stage["arn"])["stage"]["arn"] == stage["arn"]


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


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected StartComposition to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
