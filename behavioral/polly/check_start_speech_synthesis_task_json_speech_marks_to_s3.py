"""start-speech-synthesis-task-json-speech-marks-to-s3."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "start-speech-synthesis-task-json-speech-marks-to-s3"
GROUP = "async-task"
SERVICES = ["polly"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An asynchronous StartSpeechSynthesisTask with OutputFormat=json and SpeechMarkTypes
    writes a real newline-delimited speech-marks stream to S3, not just audio -- the async
    data plane must support marks output exactly like the synchronous SynthesizeSpeech path."""
    polly = ctx.client("polly")
    bucket = _create_bucket(ctx)
    text = "Hello world. This is an asynchronous speech marks check."

    task_id = polly.start_speech_synthesis_task(
        Engine="standard",
        OutputFormat="json",
        OutputS3BucketName=bucket,
        SpeechMarkTypes=["sentence", "word"],
        Text=text,
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
    s3 = ctx.client("s3")
    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode("utf-8")
    lines = [line for line in body.strip().split("\n") if line]
    assert len(lines) > 0, "no speech marks written to S3"
    marks = [json.loads(line) for line in lines]
    types = {m["type"] for m in marks}
    assert "sentence" in types and "word" in types, types


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-polly-tts-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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
