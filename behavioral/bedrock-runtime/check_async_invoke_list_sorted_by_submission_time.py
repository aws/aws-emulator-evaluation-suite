"""async-invoke-list-sorted-by-submission-time."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "async-invoke-list-sorted-by-submission-time"
GROUP = "ordering"
SERVICES = ["bedrock-runtime"]

# luma.ray-v2:0 is a VIDEO-capable async model; a 5 s job Completes in about 71 s.
ASYNC_MODEL = "luma.ray-v2:0"

# submitTime is only distinguishable at whole-second granularity, so the second
# submission must be delayed until the wall clock crosses into a new second
# relative to the first submission's own reported submitTime -- never a blind sleep.
SUBMIT_GAP_DEADLINE_S = 15.0


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListAsyncInvokes returns items in a stable, consistent submission-time order across repeated calls."""
    bucket = _create_output_bucket(ctx)
    br = ctx.client("bedrock-runtime")
    arn_older = _start_video_invoke(
        ctx, bucket, prompt="A small sailboat drifting on a calm lake at sunrise."
    )
    submit_older = br.get_async_invoke(invocationArn=arn_older)["submitTime"]

    deadline = time.monotonic() + SUBMIT_GAP_DEADLINE_S
    while time.monotonic() < deadline and int(time.time()) == int(submit_older.timestamp()):
        time.sleep(0.5)
    assert int(time.time()) != int(submit_older.timestamp()), (
        f"wall clock never crossed past the first submission's reported second "
        f"({submit_older}) within {SUBMIT_GAP_DEADLINE_S}s"
    )

    arn_newer = _start_video_invoke(
        ctx, bucket, prompt="A red kite flying high above a green hill."
    )
    submit_newer = br.get_async_invoke(invocationArn=arn_newer)["submitTime"]
    assert submit_newer > submit_older, (
        f"expected the second invocation's own reported submitTime ({submit_newer}) to be "
        f"strictly after the first's ({submit_older})"
    )

    order_1 = _find_relative_order(ctx, arn_older, arn_newer)
    assert len(order_1) == 2, f"expected both invocations discoverable, found {order_1}"
    assert order_1 == [arn_newer, arn_older], (
        "requesting sortBy=SubmissionTime, sortOrder=Descending should list the "
        "more-recently-submitted job first"
    )

    order_2 = _find_relative_order(ctx, arn_older, arn_newer)
    assert order_2 == order_1, "repeated ListAsyncInvokes calls must return a stable relative order"


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


def _start_video_invoke(ctx: Any, bucket_name: str, prompt: str) -> str:
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


def _find_relative_order(ctx: Any, arn_a: str, arn_b: str) -> list[str]:
    br = ctx.client("bedrock-runtime")
    wanted = {arn_a, arn_b}
    seen: list[str] = []
    next_token = None
    for _ in range(50):
        kwargs: dict[str, Any] = {
            "sortBy": "SubmissionTime",
            "sortOrder": "Descending",
            "maxResults": 100,
        }
        if next_token:
            kwargs["nextToken"] = next_token
        page = br.list_async_invokes(**kwargs)
        for summary in page.get("asyncInvokeSummaries", []):
            arn = summary["invocationArn"]
            if arn in wanted and arn not in seen:
                seen.append(arn)
        next_token = page.get("nextToken")
        if len(seen) == len(wanted) or not next_token:
            break
    return seen


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
