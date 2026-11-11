"""start-speech-synthesis-task-output-s3-key-prefix-applied."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "start-speech-synthesis-task-output-s3-key-prefix-applied"
GROUP = "async-task"
SERVICES = ["polly"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """When OutputS3KeyPrefix is provided, the completed task's object is actually written
    under that prefix in the S3 bucket -- not ignored or written to a default location."""
    polly = ctx.client("polly")
    bucket = _create_bucket(ctx)
    prefix = "custom-prefix"

    task_id = polly.start_speech_synthesis_task(
        Engine="standard",
        OutputFormat="mp3",
        OutputS3BucketName=bucket,
        OutputS3KeyPrefix=prefix,
        Text="Checking that the S3 key prefix is honored.",
        VoiceId="Joanna",
    )["SynthesisTask"]["TaskId"]

    final = _poll_until(
        lambda: polly.get_speech_synthesis_task(TaskId=task_id)["SynthesisTask"],
        lambda t: t["TaskStatus"] in ("completed", "failed"),
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert final["TaskStatus"] == "completed", final.get("TaskStatusReason")

    key = _s3_key_from_uri(final["OutputUri"], bucket)
    assert key.startswith(prefix), key

    s3 = ctx.client("s3")
    listing = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
    keys = {obj["Key"] for obj in listing.get("Contents", [])}
    assert key in keys, keys


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-polly-tts-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":  # us-east-1 is the one region CreateBucket rejects a LocationConstraint for
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=name)
    for obj in resp.get("Contents", []):
        s3.delete_object(Bucket=name, Key=obj["Key"])
    s3.delete_bucket(Bucket=name)


def _s3_key_from_uri(output_uri: str, bucket: str) -> str:
    from urllib.parse import urlparse

    parsed = urlparse(output_uri)
    path = parsed.path.lstrip("/")
    if parsed.netloc.startswith(bucket + "."):
        return path
    parts = path.split("/", 1)
    assert parts[0] == bucket, (parts, bucket)
    return parts[1]


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
