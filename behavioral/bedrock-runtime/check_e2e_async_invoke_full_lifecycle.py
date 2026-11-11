"""e2e-async-invoke-full-lifecycle."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-async-invoke-full-lifecycle"
GROUP = "state-machine"
SERVICES = ["bedrock-runtime"]

# luma.ray-v2:0 is a current video-capable async model in this suite's region.
ASYNC_MODEL = "luma.ray-v2:0"


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An async video invoke runs to Completed, is listed by ListAsyncInvokes with
    statusEquals=Completed, and leaves a non-empty output artifact under its S3 output prefix."""
    bucket = _create_output_bucket(ctx)
    arn = _start_video_invoke(ctx, bucket)
    final = _poll_async_invoke(ctx, arn, timeout_s=900.0, interval_s=15.0)
    assert final["status"] == "Completed", (
        f"expected terminal Completed status, got {final['status']} ({final.get('failureMessage')})"
    )

    br = ctx.client("bedrock-runtime")
    found = None
    next_token = None
    for _ in range(50):
        kwargs: dict[str, Any] = {"statusEquals": "Completed", "maxResults": 100}
        if next_token:
            kwargs["nextToken"] = next_token
        page = br.list_async_invokes(**kwargs)
        for summary in page.get("asyncInvokeSummaries", []):
            if summary["invocationArn"] == arn:
                found = summary
                break
        next_token = page.get("nextToken")
        if found or not next_token:
            break

    assert found is not None, (
        "completed invocation should be discoverable via ListAsyncInvokes(statusEquals=Completed)"
    )
    assert found["status"] == "Completed"

    s3_uri = final["outputDataConfig"]["s3OutputDataConfig"]["s3Uri"]
    prefix = _s3_uri_to_key_prefix(s3_uri, bucket)
    assert _object_exists_under_prefix(ctx, bucket, prefix), (
        "the completion output artifact should be the observable consequence in S3"
    )


def _create_output_bucket(ctx: Any) -> str:
    # In the region the job runs in, so Bedrock's async-invoke output destination is reachable.
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-bedrock-async-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "bedrock-e2e-async-invoke-full-lifecycle"}]}
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
        ctx,
        lambda: br.start_async_invoke(
            modelId=ASYNC_MODEL,
            modelInput=model_input,
            outputDataConfig=output_config,
        )
    )
    return resp["invocationArn"]


def _start_with_backoff(ctx, fn):
    """Retry ONLY a throttle: an account admits very few concurrent async invocations, so
    async-invoke jobs started at once can throttle each other."""
    left = ctx.time_left()
    deadline = time.monotonic() + (180.0 if left is None else min(180.0, left))
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
    ctx: Any, arn: str, timeout_s: float = 900.0, interval_s: float = 15.0
) -> dict[str, Any]:
    br = ctx.client("bedrock-runtime")
    deadline = time.monotonic() + timeout_s
    record = br.get_async_invoke(invocationArn=arn)
    while record["status"] == "InProgress" and time.monotonic() < deadline:
        time.sleep(interval_s)
        record = br.get_async_invoke(invocationArn=arn)
    return record


def _s3_uri_to_key_prefix(s3_uri: str, bucket: str) -> str:
    assert s3_uri.startswith(f"s3://{bucket}/")
    return s3_uri[len(f"s3://{bucket}/") :]


def _object_exists_under_prefix(ctx: Any, bucket: str, prefix: str) -> bool:
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
    return any(obj["Size"] > 0 for obj in resp.get("Contents", []))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
