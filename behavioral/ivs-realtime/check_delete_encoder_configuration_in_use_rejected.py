"""delete-encoder-configuration-in-use-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-encoder-configuration-in-use-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs-realtime"]


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")



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
    """DeleteEncoderConfiguration is rejected while an active Composition still references it."""
    ivs = ctx.client("ivs-realtime")
    tags_kw = {"tags": {"sim2real": CHECK}}
    bucket = _create_bucket(ctx)

    # Positive control, before anything is broken: deleting an encoder configuration that no
    # Composition references succeeds. Without this, "rejects the in-use encoder" would be
    # indistinguishable from "rejects every DeleteEncoderConfiguration".
    control_arn = ivs.create_encoder_configuration(
        name=ctx.unique_name("sim2real-enc-ctrl-"), **tags_kw
    )["encoderConfiguration"]["arn"]
    ivs.delete_encoder_configuration(arn=control_arn)
    control_remaining = [c["arn"] for c in ivs.list_encoder_configurations()["encoderConfigurations"]]
    assert control_arn not in control_remaining, (
        f"control: an unreferenced encoder configuration must delete cleanly; "
        f"{control_arn} still listed in {control_remaining!r}"
    )

    stage_arn = ivs.create_stage(name=ctx.unique_name("sim2real-stage-"), **tags_kw)["stage"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_stage(arn=stage_arn))
    encoder_arn = ivs.create_encoder_configuration(name=ctx.unique_name("sim2real-enc-"), **tags_kw)[
        "encoderConfiguration"
    ]["arn"]
    encoder_deleted = False

    def _cleanup_encoder():
        if not encoder_deleted:
            ivs.delete_encoder_configuration(arn=encoder_arn)

    ctx.on_cleanup(_cleanup_encoder)

    storage_arn = ivs.create_storage_configuration(
        name=ctx.unique_name("sim2real-storage-"), s3={"bucketName": bucket}, **tags_kw
    )["storageConfiguration"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_storage_configuration(arn=storage_arn))

    comp_arn = ivs.start_composition(
        stageArn=stage_arn,
        destinations=[
            {"s3": {"storageConfigurationArn": storage_arn, "encoderConfigurationArns": [encoder_arn]}}
        ],
        **tags_kw,
    )["composition"]["arn"]

    _poll_until(
        lambda: ivs.get_composition(arn=comp_arn)["composition"],
        lambda c: c["state"] == "ACTIVE",
        timeout_s=60.0,
    )

    # Break exactly one thing: while the composition is actively using it, deletion must be
    # rejected.
    in_use = _client_error(lambda: ivs.delete_encoder_configuration(arn=encoder_arn))
    assert in_use.get("Code") == "ConflictException", (
        f"expected ConflictException deleting an encoder configuration referenced by an ACTIVE "
        f"composition; got {in_use!r}"
    )
    assert in_use.get("Message") == (
        f"Resource: {encoder_arn} is attached to a composition"
    ), in_use

    # Effect absent: the encoder configuration is still there.
    still_there = [c["arn"] for c in ivs.list_encoder_configurations()["encoderConfigurations"]]
    assert encoder_arn in still_there, (
        f"expected {encoder_arn} to still be listed after the rejected delete; got {still_there!r}"
    )

    ivs.stop_composition(arn=comp_arn)
    _poll_until(
        lambda: ivs.get_composition(arn=comp_arn)["composition"],
        lambda c: c["state"] in ("STOPPED", "FAILED"),
        timeout_s=60.0,
    )

    # Restore: once the composition is no longer active, the identical delete call now succeeds.
    ivs.delete_encoder_configuration(arn=encoder_arn)
    encoder_deleted = True
    remaining = [c["arn"] for c in ivs.list_encoder_configurations()["encoderConfigurations"]]
    assert encoder_arn not in remaining, (
        f"expected {encoder_arn} gone from ListEncoderConfigurations after delete; got {remaining!r}"
    )
    deleted = _client_error(lambda: ivs.get_encoder_configuration(arn=encoder_arn))
    assert deleted.get("Code") == "ResourceNotFoundException", (
        f"expected GetEncoderConfiguration on the deleted arn to report ResourceNotFoundException; "
        f"got {deleted!r}"
    )
    assert deleted.get("Message") == f"Resource: {encoder_arn} not found", deleted


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
