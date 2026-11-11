"""async-invoke-terminal-state-immutable."""
from __future__ import annotations

import random
import time
from typing import Any

from behavioral_harness import tags

CHECK = "async-invoke-terminal-state-immutable"
GROUP = "state-machine"
SERVICES = ["bedrock-runtime"]

# Amazon Nova Reel is not offered in us-west-2: StartAsyncInvoke there rejects every form of the
# model id with ValidationException, and ListFoundationModels lists it only in us-east-1.
MODEL_REGION = "us-east-1"


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Once an async invocation is terminal, repeated GetAsyncInvoke calls return identical output."""
    bucket = _create_output_bucket(ctx)
    arn = _start_video_invoke(ctx, bucket)
    final = _poll_async_invoke(ctx, arn, timeout_s=900.0, interval_s=15.0)
    assert final["status"] == "Completed", (
        f"expected terminal Completed status, got {final['status']} ({final.get('failureMessage')})"
    )

    br = ctx.client("bedrock-runtime", region=MODEL_REGION)
    for _ in range(3):
        time.sleep(5)
        again = br.get_async_invoke(invocationArn=arn)
        assert again["status"] == final["status"], "terminal status must not change on re-read"
        assert again["outputDataConfig"] == final["outputDataConfig"], (
            "outputDataConfig must be immutable once terminal"
        )
        assert again["endTime"] == final["endTime"], "endTime must be immutable once terminal"


def _create_output_bucket(ctx: Any) -> str:
    # Created in MODEL_REGION, not ctx.region: Bedrock's S3 output destination for async invoke
    # must be reachable from the region the job actually runs in.
    s3 = ctx.client("s3", region=MODEL_REGION)
    name = ctx.unique_name("sim2real-bedrock-async-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if MODEL_REGION != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": MODEL_REGION}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "bedrock-async-invoke-terminal-state-immutable"}]}
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
    br = ctx.client("bedrock-runtime", region=MODEL_REGION)
    seed = random.randint(0, 2147483646)
    model_input = {
        "taskType": "TEXT_VIDEO",
        "textToVideoParams": {"text": prompt},
        "videoGenerationConfig": {
            "fps": 24,
            "durationSeconds": 6,
            "dimension": "1280x720",
            "seed": seed,
        },
    }
    output_config = {"s3OutputDataConfig": {"s3Uri": f"s3://{bucket_name}/"}}
    resp = br.start_async_invoke(
        modelId="amazon.nova-reel-v1:1",
        modelInput=model_input,
        outputDataConfig=output_config,
    )
    return resp["invocationArn"]


def _poll_async_invoke(
    ctx: Any, arn: str, timeout_s: float = 900.0, interval_s: float = 15.0
) -> dict[str, Any]:
    br = ctx.client("bedrock-runtime", region=MODEL_REGION)
    deadline = time.monotonic() + timeout_s
    record = br.get_async_invoke(invocationArn=arn)
    while record["status"] == "InProgress" and time.monotonic() < deadline:
        time.sleep(interval_s)
        record = br.get_async_invoke(invocationArn=arn)
    return record


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
