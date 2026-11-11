"""start-composition-idempotency-token-accepted."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-composition-idempotency-token-accepted"
GROUP = "temporal"
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
    """Replaying StartComposition's idempotencyToken on the same stage fails ConflictException with the exact
    message and adds no composition, while a different token starts a second, distinct composition."""
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

    # Positive control: the token is accepted and creates a real Composition.
    token_a = ctx.unique_name("sim2real-idem-a-")
    first = ivs.start_composition(
        stageArn=stage_arn,
        destinations=destinations,
        idempotencyToken=token_a,
    )["composition"]
    ctx.on_cleanup(lambda: _safe_stop(ivs, first["arn"]))

    # Replaying the IDENTICAL token against the same stage/destinations is rejected
    # with the specific ConflictException, not silently deduped and not accepted as
    # a second composition.
    try:
        ivs.start_composition(
            stageArn=stage_arn,
            destinations=destinations,
            idempotencyToken=token_a,
        )
    except ClientError as e:
        error = e.response["Error"]
        assert error.get("Code") == "ConflictException", (
            f"expected ConflictException replaying idempotencyToken {token_a!r}, got {error!r}"
        )
        assert error.get("Message") == (
            "A composition resource already exists with the given attributes"
        ), error
    else:
        raise AssertionError(
            f"replaying idempotencyToken {token_a!r} unexpectedly succeeded instead of "
            "raising ConflictException"
        )

    # A DIFFERENT token against the same stage still succeeds with a distinct
    # Composition -- the ConflictException above is about token reuse, not the
    # stage refusing a second composition outright.
    second = ivs.start_composition(
        stageArn=stage_arn,
        destinations=destinations,
        idempotencyToken=ctx.unique_name("sim2real-idem-b-"),
    )["composition"]
    ctx.on_cleanup(lambda: _safe_stop(ivs, second["arn"]))

    assert first["arn"] != second["arn"], (first["arn"], second["arn"])

    for comp_arn in (first["arn"], second["arn"]):
        state = _poll_until(
            lambda a=comp_arn: ivs.get_composition(arn=a)["composition"],
            lambda c: c["state"] in ("ACTIVE", "STOPPED", "FAILED"),
            timeout_s=60.0,
        )["state"]
        assert state in ("ACTIVE", "STOPPED"), state

    # Exactly two distinct compositions exist for this stage: the rejected replay
    # left no third one behind.
    matching = {
        c["arn"] for c in ivs.list_compositions(filterByStageArn=stage_arn)["compositions"]
    }
    assert {first["arn"], second["arn"]} <= matching, matching
    assert len(matching) == 2, (
        f"the rejected token-reuse call must not leave a third composition behind; "
        f"found {matching}"
    )


def _safe_stop(ivs, arn):
    """Stop the composition and wait for it to settle, so the encoder and storage
    configurations it references can be deleted afterwards."""
    try:
        ivs.stop_composition(arn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    _poll_until(
        lambda: ivs.get_composition(arn=arn)["composition"],
        lambda c: c["state"] in ("STOPPED", "FAILED"),
        timeout_s=90.0,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

