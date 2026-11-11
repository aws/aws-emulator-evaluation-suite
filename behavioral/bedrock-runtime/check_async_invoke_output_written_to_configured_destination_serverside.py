"""async-invoke-output-written-to-configured-destination-serverside."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "async-invoke-output-written-to-configured-destination-serverside"
GROUP = "server-side"
SERVICES = ["bedrock-runtime"]

VIDEO_MODEL = "luma.ray-v2:0"


def _wait_terminal(ctx, arn: str, timeout_s: float = 360.0, interval_s: float = 10.0) -> dict:
    bedrock = ctx.client("bedrock-runtime")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = bedrock.get_async_invoke(invocationArn=arn)
        status = resp
        if resp["status"] != "InProgress":
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"async invoke did not reach a terminal state within {timeout_s}s (last={status})")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A StartAsyncInvoke video job reaches Completed and the service itself writes output.mp4 and a
    non-empty manifest.json under the S3 prefix named in outputDataConfig; the client uploads
    nothing.
    """
    s3 = ctx.client("s3")
    bedrock = ctx.client("bedrock-runtime")
    bucket = ctx.unique_name("sim2real-behav-async-out-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "bedrock-runtime-async-invoke-output-serverside"}]})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    prefix = "video-out"
    resp = bedrock.start_async_invoke(
        modelId=VIDEO_MODEL,
        modelInput={
            "prompt": "A calm ocean at sunrise, gentle waves",
            "aspect_ratio": "16:9",
            "duration": "5s",
            "resolution": "540p",
        },
        outputDataConfig={"s3OutputDataConfig": {"s3Uri": f"s3://{bucket}/{prefix}"}},
    )
    invocation_arn = resp["invocationArn"]

    def _cleanup_objects():
        objs = s3.list_objects_v2(Bucket=bucket, Prefix=prefix).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])

    ctx.on_cleanup(_cleanup_objects)

    final = _wait_terminal(ctx, invocation_arn)
    assert final["status"] == "Completed", f"video generation did not complete: {final}"

    invocation_id = invocation_arn.split("/")[-1]
    listing = s3.list_objects_v2(Bucket=bucket, Prefix=f"{prefix}/{invocation_id}/")
    keys = [o["Key"] for o in listing.get("Contents", [])]
    assert any(k.endswith("manifest.json") for k in keys), keys
    assert any(k.endswith("output.mp4") for k in keys), keys

    manifest_key = next(k for k in keys if k.endswith("manifest.json"))
    manifest_body = s3.get_object(Bucket=bucket, Key=manifest_key)["Body"].read()
    manifest = json.loads(manifest_body)
    assert isinstance(manifest, dict) and manifest, (
        f"manifest.json at {manifest_key!r} did not parse to a non-empty JSON object: {manifest_body!r}"
    )
    request_id = manifest.get("requestId")
    assert request_id and str(uuid.UUID(request_id)) == request_id, (
        f"manifest.json at {manifest_key!r} did not report a canonical UUID requestId: {manifest!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
