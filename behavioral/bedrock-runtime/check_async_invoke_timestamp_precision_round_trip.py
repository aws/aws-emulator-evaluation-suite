"""async-invoke-timestamp-precision-round-trip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "async-invoke-timestamp-precision-round-trip"
GROUP = "server-side"
SERVICES = ["bedrock-runtime"]

# luma.ray-v2:0 is a VIDEO-capable async model; a 5 s job Completes in about 71 s.
VIDEO_MODEL = "luma.ray-v2:0"


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


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An async job's submitTime is stable across GetAsyncInvoke reads, and once Completed its
    endTime is strictly after submitTime with lastModifiedTime at or after endTime."""
    s3 = ctx.client("s3")
    bedrock = ctx.client("bedrock-runtime")
    bucket = ctx.unique_name("sim2real-behav-async-ts-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]})

    def _cleanup_bucket():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup_bucket)

    resp = _start_with_backoff(lambda: bedrock.start_async_invoke(
        modelId=VIDEO_MODEL,
        modelInput={
            "prompt": "A slow pan across a quiet forest",
            "aspect_ratio": "16:9",
            "loop": False,
            "duration": "5s",
            "resolution": "540p",
        },
        outputDataConfig={"s3OutputDataConfig": {"s3Uri": f"s3://{bucket}/out/"}},
        tags=[{"key": "simparity-check", "value": CHECK}],
    ))
    invocation_arn = resp["invocationArn"]

    get_1 = bedrock.get_async_invoke(invocationArn=invocation_arn)
    get_2 = bedrock.get_async_invoke(invocationArn=invocation_arn)
    submit_time = get_1["submitTime"]
    assert submit_time == get_2["submitTime"], "submitTime must be stable across repeated reads"

    deadline = time.monotonic() + 240.0
    final = None
    while time.monotonic() < deadline:
        final = bedrock.get_async_invoke(invocationArn=invocation_arn)
        if final["status"] != "InProgress":
            break
        time.sleep(2)
    assert final is not None and final["status"] == "Completed", f"job did not complete: {final}"

    assert final["submitTime"] == submit_time, "submitTime must not drift once recorded"
    assert final["endTime"] > final["submitTime"], "endTime must be strictly after submitTime"
    assert final["lastModifiedTime"] >= final["endTime"], "lastModifiedTime must not precede endTime"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
