"""get-composition-not-found-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-composition-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["ivs-realtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetComposition on an ARN that doesn't reference an existing composition is
    rejected with ResourceNotFoundException, proven against a target where GetComposition
    itself demonstrably succeeds on a real, active composition."""
    ivsrt = ctx.client("ivs-realtime")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bucket = _create_bucket(ctx)

    stage_arn = ivsrt.create_stage(
        name=ctx.unique_name("sim2real-stage-"), tags={"sim2real": CHECK}
    )["stage"]["arn"]
    ctx.on_cleanup(lambda: ivsrt.delete_stage(arn=stage_arn))
    encoder_arn = ivsrt.create_encoder_configuration(
        name=ctx.unique_name("sim2real-enc-"), tags={"sim2real": CHECK}
    )["encoderConfiguration"]["arn"]
    ctx.on_cleanup(lambda: ivsrt.delete_encoder_configuration(arn=encoder_arn))
    storage_arn = ivsrt.create_storage_configuration(
        name=ctx.unique_name("sim2real-storage-"),
        s3={"bucketName": bucket},
        tags={"sim2real": CHECK},
    )["storageConfiguration"]["arn"]
    ctx.on_cleanup(lambda: ivsrt.delete_storage_configuration(arn=storage_arn))

    comp_arn = ivsrt.start_composition(
        stageArn=stage_arn,
        destinations=[
            {"s3": {"storageConfigurationArn": storage_arn, "encoderConfigurationArns": [encoder_arn]}}
        ],
    )["composition"]["arn"]
    ctx.on_cleanup(lambda: _safe_stop(ivsrt, comp_arn))

    # Positive control: GetComposition succeeds on a real, active composition.
    active = _poll_until(
        lambda: ivsrt.get_composition(arn=comp_arn)["composition"],
        lambda c: c["state"] == "ACTIVE",
        timeout_s=60.0,
    )
    assert active["arn"] == comp_arn, (active.get("arn"), comp_arn)

    # GetComposition on an ARN that never referenced a composition is rejected.
    bogus_arn = f"arn:aws:ivs:{ctx.region}:{account}:composition/{uuid.uuid4().hex[:12]}"
    code, message = _error(lambda: ivsrt.get_composition(arn=bogus_arn))
    assert code == "ResourceNotFoundException", code
    assert message == f"Resource: {bogus_arn} not found", message


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


def _safe_stop(ivsrt, arn):
    """Stop the composition and wait until it is terminal, so the encoder and storage
    configurations it holds can be deleted next."""
    try:
        ivsrt.stop_composition(arn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    _poll_until(
        lambda: ivsrt.get_composition(arn=arn)["composition"],
        lambda c: c["state"] in ("STOPPED", "FAILED"),
        timeout_s=90.0,
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises, so a target that
    accepts what AWS refuses never reads as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
