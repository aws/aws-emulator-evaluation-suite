"""start-async-invoke-lifecycle-and-idempotency."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-async-invoke-lifecycle-and-idempotency"
GROUP = "state"
SERVICES = ["bedrock-runtime"]

# Nova Reel is rejected as an invalid model identifier in this region; luma.ray-v2:0 is the
# video-output model ListFoundationModels offers here.
MODEL_ID = "luma.ray-v2:0"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartAsyncInvoke token replays return the original ARN even with a different modelInput, but
    a different outputDataConfig is a ConflictException that leaves the job untouched; the job then
    completes, is listed as Completed, and writes its video under the derived S3 prefix."""
    brt = ctx.client("bedrock-runtime")
    bucket = _create_bucket(ctx)
    token = ctx.unique_name("sim2real-behav-async-")

    model_input_a = {
        "prompt": "A single red ball rolling across a white floor.",
        "aspect_ratio": "16:9",
        "loop": False,
        "duration": "5s",
        "resolution": "540p",
    }
    output_config_a = {"s3OutputDataConfig": {"s3Uri": f"s3://{bucket}/out/"}}

    started = _start_with_backoff(
        lambda: brt.start_async_invoke(
            clientRequestToken=token,
            modelId=MODEL_ID,
            modelInput=model_input_a,
            outputDataConfig=output_config_a,
        )
    )
    invocation_arn = started["invocationArn"]
    invocation_id = invocation_arn.rsplit("/", 1)[-1]
    assert invocation_id, f"the returned ARN carries no invocation id; got {invocation_arn!r}"
    # The service appends the minted invocation id to the requested prefix.
    expected_output_uri = f"s3://{bucket}/out/{invocation_id}"

    replay = _start_with_backoff(
        lambda: brt.start_async_invoke(
            clientRequestToken=token,
            modelId=MODEL_ID,
            modelInput=model_input_a,
            outputDataConfig=output_config_a,
        )
    )
    assert replay["invocationArn"] == invocation_arn, "idempotent replay should return the same invocationArn"

    # modelInput is not part of the idempotency conflict key.
    model_input_b = {
        "prompt": "A completely different scene: a red sphere bouncing on a wooden floor.",
        "aspect_ratio": "16:9",
        "loop": False,
        "duration": "5s",
        "resolution": "540p",
    }
    tolerated = _start_with_backoff(
        lambda: brt.start_async_invoke(
            clientRequestToken=token,
            modelId=MODEL_ID,
            modelInput=model_input_b,
            outputDataConfig=output_config_a,
        )
    )
    assert tolerated["invocationArn"] == invocation_arn, (
        f"a same-token replay with only modelInput changed should still resolve to the original "
        f"job (modelInput is not part of the conflict key), got {tolerated['invocationArn']!r} "
        f"vs original {invocation_arn!r}"
    )

    # outputDataConfig is part of the conflict key.
    output_config_conflicting = {"s3OutputDataConfig": {"s3Uri": f"s3://{bucket}/conflicting/"}}
    try:
        conflicted = brt.start_async_invoke(
            clientRequestToken=token,
            modelId=MODEL_ID,
            modelInput=model_input_a,
            outputDataConfig=output_config_conflicting,
        )
    except ClientError as exc:
        conflict_code = exc.response["Error"]["Code"]
        conflict_message = exc.response["Error"].get("Message", "")
    else:
        raise AssertionError(
            f"a same-token replay with a different outputDataConfig must be refused, but it "
            f"SUCCEEDED and returned {conflicted!r}"
        )
    assert conflict_code == "ConflictException", (
        f"a same-token replay with a different outputDataConfig must be rejected with "
        f"ConflictException, got {conflict_code!r}"
    )
    assert conflict_message == (
        "Received a request with a client request token that has been used for a different input."
    ), conflict_message

    unaffected = brt.get_async_invoke(invocationArn=invocation_arn)
    assert unaffected["invocationArn"] == invocation_arn, (
        f"the rejected conflicting call should leave the original job untouched, got {unaffected['invocationArn']!r}"
    )
    assert unaffected["outputDataConfig"]["s3OutputDataConfig"]["s3Uri"] == expected_output_uri, (
        f"the rejected conflicting call's outputDataConfig must have no effect on the original "
        f"job, expected {expected_output_uri!r} got {unaffected['outputDataConfig']!r}"
    )

    final = _poll_until(
        lambda: brt.get_async_invoke(invocationArn=invocation_arn),
        lambda r: r["status"] != "InProgress",
        timeout_s=240,
        interval_s=10,
    )
    assert final["status"] == "Completed", final.get("failureMessage")
    assert final["outputDataConfig"]["s3OutputDataConfig"]["s3Uri"] == expected_output_uri, (
        f"completed job's outputDataConfig should still name the derived destination, "
        f"expected {expected_output_uri!r} got {final['outputDataConfig']!r}"
    )

    # Paginated: other completed invocations in the account can push this one off page one.
    arns: set[str] = set()
    for page in brt.get_paginator("list_async_invokes").paginate(statusEquals="Completed"):
        arns.update(s["invocationArn"] for s in page["asyncInvokeSummaries"])
    assert invocation_arn in arns, "completed invocation missing from ListAsyncInvokes(statusEquals=Completed)"

    s3 = ctx.client("s3")
    listing = s3.list_objects_v2(Bucket=bucket, Prefix=f"out/{invocation_id}/")
    keys = [obj["Key"] for obj in listing.get("Contents", [])]
    assert any(key.endswith("manifest.json") for key in keys), keys
    assert any(key.endswith(".mp4") for key in keys), (
        f"completion claims the output was written but no video artifact is at the destination: {keys}"
    )


def _start_with_backoff(fn):
    """Start the invocation, retrying only ThrottlingException for up to 180s.

    The async invoke concurrency quota is very low, so concurrent invocations throttle.
    """
    deadline = time.monotonic() + 180
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ThrottlingException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-async-out-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [
            {"Key": "sim2real-check", "Value": CHECK},
            # Lets a bucket that survives a failed teardown be found and removed later.
            {"Key": "sim2real:managed", "Value": "true"},
        ]},
    )

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last result: {result}")
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
