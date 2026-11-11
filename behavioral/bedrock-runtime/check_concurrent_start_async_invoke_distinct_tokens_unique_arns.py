"""concurrent-start-async-invoke-distinct-tokens-unique-arns."""
from __future__ import annotations

import random
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.client import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-start-async-invoke-distinct-tokens-unique-arns"
GROUP = "concurrency"
SERVICES = ["bedrock-runtime"]

# The async-invoke quota for luma.ray-v2:0 admits little concurrency: 4 racers do not all
# clear ThrottlingException within a 240s jittered backoff, while 2 do. The invariant under test
# (distinct concurrent clientRequestTokens never collide on one invocationArn) needs N>=2, not a
# specific N.
_RACER_COUNT = 2

# StartAsyncInvoke rejects amazon.nova-reel-v1:1 here with ValidationException("The provided
# model identifier is invalid."), leaving luma.ray-v2:0 as the video-capable model.
ASYNC_MODEL = "luma.ray-v2:0"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Firing multiple StartAsyncInvoke calls concurrently, each with its own distinct
    clientRequestToken, always produces distinct, non-colliding invocationArns -- the
    server must not race and coalesce independent jobs under load."""
    client = ctx.client("bedrock-runtime")
    # A single-attempt client for the racing StartAsyncInvoke calls: botocore's own retry-with-
    # backoff would otherwise absorb a ThrottlingException for tens of seconds before ever handing
    # it to _start_with_backoff, so our own jittered pacing (below) never gets a turn.
    racer_client = ctx.client("bedrock-runtime", config=Config(retries={"max_attempts": 1}))
    bucket = _create_output_bucket(ctx)

    def _start(i: int) -> str:
        resp = _start_with_backoff(
            lambda: racer_client.start_async_invoke(
                clientRequestToken=ctx.unique_name(f"sim2real-race-{i}-"),
                modelId=ASYNC_MODEL,
                modelInput={
                    "prompt": f"Racer job number {i}: a spinning pinwheel.",
                    "aspect_ratio": "16:9",
                    "loop": False,
                    "duration": "5s",
                    "resolution": "540p",
                },
                outputDataConfig={"s3OutputDataConfig": {"s3Uri": f"s3://{bucket}/racer-{i}/"}},
                tags=[{"key": "simparity-check", "value": CHECK}],
            )
        )
        return resp["invocationArn"]

    with ThreadPoolExecutor(max_workers=_RACER_COUNT) as pool:
        arns = list(pool.map(_start, range(_RACER_COUNT)))

    assert len(arns) == _RACER_COUNT, f"expected {_RACER_COUNT} racer results, got {len(arns)}"
    assert len(set(arns)) == _RACER_COUNT, f"expected {_RACER_COUNT} unique ARNs, got {arns}"
    for arn in arns:
        assert arn.startswith("arn:aws"), f"expected an arn:aws invocationArn, got {arn!r}"
        status = client.get_async_invoke(invocationArn=arn)["status"]
        assert status in ("InProgress", "Completed"), (
            f"expected InProgress or Completed for {arn}, got {status}"
        )


def _start_with_backoff(fn):
    """Retry ONLY a throttle: the account admits very few concurrent async invocations, so firing
    _RACER_COUNT StartAsyncInvoke calls at once throttles against each other. Jittered so the
    _RACER_COUNT racers do not retry in lockstep and re-collide on the same instant. Bounded, and
    not an assertion, so it does not soften anything the check claims."""
    deadline = time.monotonic() + 240.0
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ThrottlingException" or (
                time.monotonic() >= deadline
            ):
                raise
            time.sleep(random.uniform(10.0, 20.0))


def _create_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-bedrock-async-").replace("_", "-").lower()
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
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
