"""start-async-invoke-idempotent-replay-same-params."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "start-async-invoke-idempotent-replay-same-params"
GROUP = "concurrency"
SERVICES = ["bedrock-runtime"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Replaying StartAsyncInvoke with the same clientRequestToken and identical
    parameters returns the same invocationArn instead of creating a second job."""
    # Nova Reel is not invocable in every commercial region (elsewhere StartAsyncInvoke raises
    # ValidationException("The provided model identifier is invalid")); us-east-1 is where it resolves, so both the model and its output bucket are
    # pinned there rather than following ctx.region.
    client = ctx.client("bedrock-runtime", region="us-east-1")
    bucket = _create_output_bucket(ctx)
    token = ctx.unique_name("sim2real-idem-")
    kwargs = dict(
        clientRequestToken=token,
        modelId="amazon.nova-reel-v1:1",
        modelInput={
            "taskType": "TEXT_VIDEO",
            "textToVideoParams": {"text": "A slow pan across a quiet forest."},
            "videoGenerationConfig": {
                "durationSeconds": 6,
                "fps": 24,
                "dimension": "1280x720",
                "seed": 11,
            },
        },
        outputDataConfig={"s3OutputDataConfig": {"s3Uri": f"s3://{bucket}/replay/"}},
    )

    first = client.start_async_invoke(**kwargs)
    second = client.start_async_invoke(**kwargs)

    assert first["invocationArn"] == second["invocationArn"], (
        f"replaying the same clientRequestToken with identical params produced two "
        f"different jobs: {first['invocationArn']!r} vs {second['invocationArn']!r}"
    )

    # The single job must actually exist and be progressing/complete, not a stub.
    status = client.get_async_invoke(invocationArn=first["invocationArn"])["status"]
    assert status in ("InProgress", "Completed"), (
        f"expected the single idempotent job to be InProgress or Completed, got {status!r}"
    )


def _create_output_bucket(ctx) -> str:
    s3 = ctx.client("s3", region="us-east-1")
    name = ctx.unique_name("sim2real-bedrock-async-").replace("_", "-").lower()
    s3.create_bucket(Bucket=name)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3", region="us-east-1")
    for _ in range(3):
        objects = s3.list_objects_v2(Bucket=name).get("Contents", [])
        if not objects:
            break
        s3.delete_objects(
            Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objects]}
        )
        time.sleep(1)
    s3.delete_bucket(Bucket=name)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
