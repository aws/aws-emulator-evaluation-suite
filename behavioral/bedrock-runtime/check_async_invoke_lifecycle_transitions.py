"""async-invoke-lifecycle-transitions."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "async-invoke-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["bedrock-runtime"]

# luma.ray-v2:0 is a VIDEO-capable async model; a 5 s job Completes in about 71 s.
ASYNC_MODEL = "luma.ray-v2:0"


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartAsyncInvoke begins InProgress and reaches a terminal Completed state, observable via GetAsyncInvoke."""
    bucket = _create_output_bucket(ctx)
    arn = _start_video_invoke(ctx, bucket)
    br = ctx.client("bedrock-runtime")

    initial = br.get_async_invoke(invocationArn=arn)
    assert initial["invocationArn"] == arn, (
        f"expected GetAsyncInvoke to echo back {arn!r}, got {initial['invocationArn']!r}"
    )
    assert initial["status"] == "InProgress", (
        f"expected InProgress immediately after StartAsyncInvoke, got {initial['status']}"
    )

    final = _poll_async_invoke(ctx, arn, timeout_s=240.0, interval_s=2.0)
    assert final["status"] == "Completed", (
        f"expected terminal Completed status, got {final['status']} ({final.get('failureMessage')})"
    )
    assert "endTime" in final, f"expected a terminal record to carry endTime, got keys {sorted(final)}"


def _create_output_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-bedrock-async-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]}
    )

    def _cleanup() -> None:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _start_video_invoke(
    ctx: Any,
    bucket_name: str,
    prompt: str = "Closeup of a cute old steampunk robot. Camera zoom in.",
) -> str:
    br = ctx.client("bedrock-runtime")
    model_input = {
        "prompt": prompt,
        "aspect_ratio": "16:9",
        "loop": False,
        "duration": "5s",
        "resolution": "540p",
    }
    output_config = {"s3OutputDataConfig": {"s3Uri": f"s3://{bucket_name}/"}}
    resp = _start_with_backoff(
        lambda: br.start_async_invoke(
            modelId=ASYNC_MODEL,
            modelInput=model_input,
            outputDataConfig=output_config,
            tags=[{"key": "simparity-check", "value": CHECK}],
        )
    )
    return resp["invocationArn"]


def _start_with_backoff(fn):
    """Retry ONLY a throttle: an account admits very few concurrent async invocations, so two
    async-invoke jobs started at once can throttle each other. Bounded, and not an assertion,
    so it does not soften anything the check claims."""
    deadline = time.monotonic() + 180.0
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ThrottlingException" or (
                time.monotonic() >= deadline
            ):
                raise
            time.sleep(2)


def _poll_async_invoke(
    ctx: Any, arn: str, timeout_s: float = 240.0, interval_s: float = 2.0
) -> dict[str, Any]:
    """Poll GetAsyncInvoke until the status leaves InProgress; raise on timeout."""
    br = ctx.client("bedrock-runtime")
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    record = br.get_async_invoke(invocationArn=arn)
    while record["status"] == "InProgress":
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"async invoke {arn} still InProgress after {timeout_s}s: {record!r}"
            )
        time.sleep(interval_s)
        record = br.get_async_invoke(invocationArn=arn)
    return record


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
