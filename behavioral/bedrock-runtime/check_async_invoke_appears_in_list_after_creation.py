"""async-invoke-appears-in-list-after-creation."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "async-invoke-appears-in-list-after-creation"
GROUP = "state-machine"
SERVICES = ["bedrock-runtime"]

# amazon.nova-reel-v1:0 is refused in us-west-2 ("The provided model identifier is invalid").
# luma.ray-v2:0 with an empty modelInput reaches a terminal state in seconds, with no video render.
_ASYNC_MODEL = "luma.ray-v2:0"


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:representation",
    "concern:data-plane",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A newly started async invocation is listed at once by ListAsyncInvokes with matching ids."""
    bucket = _create_output_bucket(ctx)
    arn = _start_async_invoke(ctx, bucket)
    br = ctx.client("bedrock-runtime")
    control = br.get_async_invoke(invocationArn=arn)
    model_arn = control["modelArn"]

    found = None
    next_token = None
    for _ in range(50):
        kwargs: dict[str, Any] = {"maxResults": 100}
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

    assert found is not None, "newly started invocation should be immediately discoverable via ListAsyncInvokes"
    assert found["modelArn"] == model_arn, (
        f"ListAsyncInvokes reported modelArn={found['modelArn']!r} but GetAsyncInvoke on the same "
        f"invocationArn reported {model_arn!r}"
    )
    confirm = br.get_async_invoke(invocationArn=arn)
    # The later read may have moved the job forward from InProgress to a terminal status.
    assert found["status"] == confirm["status"] or (
        found["status"] == "InProgress" and confirm["status"] in ("Completed", "Failed")
    ), (
        f"ListAsyncInvokes reported status={found['status']!r} but a later GetAsyncInvoke on "
        f"the same invocationArn reported {confirm['status']!r} -- neither equal nor a forward "
        f"transition from InProgress"
    )


def _create_output_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-bedrock-async-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={
            "TagSet": [
                {"Key": "sim2real:managed", "Value": "true"},
                {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
            ]
        },
    )

    def _cleanup() -> None:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _start_async_invoke(ctx: Any, bucket_name: str) -> str:
    br = ctx.client("bedrock-runtime")
    output_config = {"s3OutputDataConfig": {"s3Uri": f"s3://{bucket_name}/"}}
    resp = br.start_async_invoke(
        modelId=_ASYNC_MODEL,
        modelInput={},
        outputDataConfig=output_config,
    )
    return resp["invocationArn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
