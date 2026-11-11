"""async-invoke-output-retention-window."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "async-invoke-output-retention-window"
GROUP = "visibility-timeout-ttl"
SERVICES = ["bedrock-runtime"]

# luma.ray-v2:0 is a current video-capable async model in this suite's region.
ASYNC_MODEL = "luma.ray-v2:0"
#: How long after completion the record and its artifact are re-read.
_WINDOW_S = 60.0


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Completed async invoke stays resolvable with an unchanged s3Uri and its S3 artifact.

    Retention is undocumented, so this only asserts a lower bound over ~60s after completion."""
    bucket = _create_output_bucket(ctx)
    arn = _start_video_invoke(ctx, bucket)
    final = _poll_async_invoke(ctx, arn, timeout_s=900.0, interval_s=15.0)
    assert final["status"] == "Completed", (
        f"expected terminal Completed status, got {final['status']} ({final.get('failureMessage')})"
    )

    s3_uri = final["outputDataConfig"]["s3OutputDataConfig"]["s3Uri"]
    prefix = _s3_uri_to_key_prefix(s3_uri, bucket)
    assert _object_exists_under_prefix(ctx, bucket, prefix), (
        "output artifact must exist in S3 immediately after completion"
    )

    br = ctx.client("bedrock-runtime")
    # Re-read every 2 s across the observation window.
    window_end = time.monotonic() + _WINDOW_S
    while True:
        again = br.get_async_invoke(invocationArn=arn)
        assert again["status"] == "Completed", "record must remain resolvable within the observation window"
        assert again["outputDataConfig"]["s3OutputDataConfig"]["s3Uri"] == s3_uri, (
            "output location reference must not change within the observation window"
        )
        assert _object_exists_under_prefix(ctx, bucket, prefix), (
            "S3 artifact must remain present within the observation window"
        )
        if time.monotonic() >= window_end:
            break
        time.sleep(2)


def _create_output_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-bedrock-async-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})

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
    assert s3_uri.startswith(f"s3://{bucket}/"), f"expected s3Uri under bucket {bucket!r}, got {s3_uri!r}"
    return s3_uri[len(f"s3://{bucket}/") :]


def _object_exists_under_prefix(ctx: Any, bucket: str, prefix: str) -> bool:
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
    return any(obj["Size"] > 0 for obj in resp.get("Contents", []))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
