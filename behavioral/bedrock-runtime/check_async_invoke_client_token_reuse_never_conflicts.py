"""async-invoke-client-token-reuse-never-conflicts."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "async-invoke-client-token-reuse-never-conflicts"
GROUP = "concurrency"
SERVICES = ["bedrock-runtime"]

ASYNC_MODEL_ID = "luma.ray-v2:0"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A clientRequestToken reused with a DIFFERENT modelInput is accepted, never ConflictException,
    and names a real job; reused with the IDENTICAL modelInput it replays the original job.
    """
    br = ctx.client("bedrock-runtime")
    bucket = _create_output_bucket(ctx)
    output_cfg = {"s3OutputDataConfig": {"s3Uri": f"s3://{bucket}/output/"}}

    # Scenario 1: reusing a token with a DIFFERENT modelInput is accepted, never ConflictException.
    # Which invocationArn it returns (the original or a fresh one) varies, so it is not pinned.
    token_mismatch = f"sim2real-{uuid.uuid4().hex}"
    model_input_a = _model_input("A single yellow taxi driving down a rainy city avenue.")
    model_input_b = _model_input("A snowy mountain peak at dawn with drifting clouds.")

    first = br.start_async_invoke(
        modelId=ASYNC_MODEL_ID,
        modelInput=model_input_a,
        outputDataConfig=output_cfg,
        clientRequestToken=token_mismatch,
    )
    arn_first = first["invocationArn"]

    mismatched = br.start_async_invoke(
        modelId=ASYNC_MODEL_ID,
        modelInput=model_input_b,
        outputDataConfig=output_cfg,
        clientRequestToken=token_mismatch,
    )
    arn_mismatched = mismatched["invocationArn"]

    # Whichever job it names, it is real: an independent read resolves it and it is progressing
    # or complete, not a stub the token collision silently dropped.
    mismatched_after = br.get_async_invoke(invocationArn=arn_mismatched)
    assert mismatched_after["invocationArn"] == arn_mismatched, (
        f"job {arn_mismatched!r} named by the mismatched-params call must resolve on an "
        f"independent read, got {mismatched_after['invocationArn']!r}"
    )
    assert mismatched_after["status"] in ("InProgress", "Completed"), (
        f"job {arn_mismatched!r} should be progressing/complete, got {mismatched_after['status']!r}"
    )
    # And the original job, whether or not it is the same job, is still there untouched.
    first_after = br.get_async_invoke(invocationArn=arn_first)
    assert first_after["invocationArn"] == arn_first, (
        f"the original job {arn_first!r} must remain resolvable after the mismatched-params "
        f"call, got {first_after['invocationArn']!r}"
    )

    # Scenario 2: reusing a token with the IDENTICAL modelInput is a true idempotent replay --
    # a fresh token, isolated from scenario 1, so scenario 1's ambiguity cannot leak into this one.
    token_replay = f"sim2real-{uuid.uuid4().hex}"
    model_input_c = _model_input("A lighthouse beam sweeping across a foggy coastline at night.")
    output_cfg_replay = {"s3OutputDataConfig": {"s3Uri": f"s3://{bucket}/replay/"}}

    original = br.start_async_invoke(
        modelId=ASYNC_MODEL_ID,
        modelInput=model_input_c,
        outputDataConfig=output_cfg_replay,
        clientRequestToken=token_replay,
    )
    arn_original = original["invocationArn"]

    replay = br.start_async_invoke(
        modelId=ASYNC_MODEL_ID,
        modelInput=model_input_c,
        outputDataConfig=output_cfg_replay,
        clientRequestToken=token_replay,
    )
    assert replay["invocationArn"] == arn_original, (
        f"idempotent replay with an identical clientRequestToken and modelInput must return the "
        f"original job {arn_original!r}, got {replay['invocationArn']!r}"
    )

    # Independent read: the replay did not spawn a second job under the hood.
    replay_after = br.get_async_invoke(invocationArn=arn_original)
    assert replay_after["status"] in ("InProgress", "Completed"), (
        f"job {arn_original!r} after idempotent replay should still be progressing/complete, "
        f"got {replay_after['status']!r}"
    )


def _model_input(text: str) -> dict:
    return {"prompt": text, "aspect_ratio": "16:9", "duration": "5s", "resolution": "540p"}


def _create_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-bedrock-async-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "bedrock-runtime-async-invoke-token-conflict"}]})

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
