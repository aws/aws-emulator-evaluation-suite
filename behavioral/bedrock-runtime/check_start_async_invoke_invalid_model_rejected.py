"""start-async-invoke-invalid-model-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "start-async-invoke-invalid-model-rejected"
GROUP = "state-machine"
SERVICES = ["bedrock-runtime"]

# The positive control needs a real async-capable model: luma.ray-v2:0 is a current
# video model in this suite's region.
ASYNC_MODEL = "luma.ray-v2:0"
_INVALID_MODEL_MESSAGE = "The provided model identifier is invalid."


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartAsyncInvoke against a modelId that does not exist is rejected with a specific,
    model-identifier-scoped ValidationException, no job is created."""
    br = ctx.client("bedrock-runtime")
    bucket = _create_output_bucket(ctx)
    model_input = {
        "prompt": "A paper airplane gliding through an office, slow motion.",
        "aspect_ratio": "16:9",
        "loop": False,
        "duration": "5s",
        "resolution": "540p",
    }
    output_cfg = {"s3OutputDataConfig": {"s3Uri": f"s3://{bucket}/bogus-model/"}}

    br.list_async_invokes(maxResults=1).get("asyncInvokeSummaries", [])

    code, message = _error_code_and_message(
        lambda: br.start_async_invoke(
            modelId="amazon.definitely-not-a-real-model-v1:0",
            modelInput=model_input,
            outputDataConfig=output_cfg,
        )
    )
    # Real AWS validates modelId shape/existence for StartAsyncInvoke as a ValidationException,
    # not ResourceNotFoundException -- unlike Converse/ConverseStream's model-lookup error class.
    # Confirmed on real AWS: both a wholly bogus id and a plausible-but-wrong-version id
    # ("amazon.nova-reel-v9:9") return the identical "model identifier is invalid" message.
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message}"
    assert message == _INVALID_MODEL_MESSAGE, (
        f"expected message {_INVALID_MODEL_MESSAGE!r}, got {message!r}"
    )

    # Effect absence: no job was created under the bogus-model output prefix.
    s3 = ctx.client("s3")
    listed = s3.list_objects_v2(Bucket=bucket, Prefix="bogus-model/")
    assert listed.get("KeyCount", 0) == 0, "a bogus StartAsyncInvoke call must not write any S3 output"

    # Positive control in the same file: a real model still starts a real job.
    # The job is polled to a terminal state, which is graded, and which also keeps it from writing
    # into the bucket after cleanup has emptied it.
    real_arn = _start_video_job(ctx, bucket)
    control = _poll_async_invoke(br, real_arn, timeout_s=300.0, interval_s=10.0)
    assert control["invocationArn"] == real_arn
    assert control["status"] == "Completed", (
        f"expected the control job to reach Completed, got {control['status']} "
        f"({control.get('failureMessage')})"
    )


def _error_code_and_message(fn):
    """Call fn(); return its (Code, Message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _poll_async_invoke(br, arn: str, *, timeout_s: float, interval_s: float) -> dict:
    """Poll GetAsyncInvoke until the status leaves InProgress; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    record = br.get_async_invoke(invocationArn=arn)
    while record["status"] == "InProgress":
        if time.monotonic() >= deadline:
            raise AssertionError(f"async invoke {arn} still InProgress after {timeout_s}s: {record!r}")
        time.sleep(interval_s)
        record = br.get_async_invoke(invocationArn=arn)
    return record


def _create_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-bedrock-async-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _start_video_job(ctx, bucket: str, text: str = "A lighthouse beam sweeping across a foggy coastline at night.") -> str:
    from botocore.exceptions import ClientError

    br = ctx.client("bedrock-runtime")
    # Retry ONLY a throttle: an account admits very few concurrent async invocations.
    left = ctx.time_left()
    deadline = time.monotonic() + (180.0 if left is None else min(180.0, left))
    while True:
        try:
            resp = br.start_async_invoke(
                modelId=ASYNC_MODEL,
                modelInput={
                    "prompt": text,
                    "aspect_ratio": "16:9",
                    "loop": False,
                    "duration": "5s",
                    "resolution": "540p",
                },
                outputDataConfig={"s3OutputDataConfig": {"s3Uri": f"s3://{bucket}/output/"}},
            )
            return resp["invocationArn"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ThrottlingException" or (
                time.monotonic() >= deadline
            ):
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
