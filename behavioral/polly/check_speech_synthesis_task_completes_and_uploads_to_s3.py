"""speech-synthesis-task-completes-and-uploads-to-s3."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "speech-synthesis-task-completes-and-uploads-to-s3"
GROUP = "e2e-pipeline"
SERVICES = ["polly"]




@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartSpeechSynthesisTask progresses scheduled -> (inProgress) -> completed
    and Polly actually uploads the rendered audio to the caller's S3 bucket
    with the OutputFormat's content type -- not just a fake state transition."""
    polly = ctx.client("polly")
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    prefix = "synth"

    started = polly.start_speech_synthesis_task(
        OutputFormat="mp3",
        OutputS3BucketName=bucket,
        OutputS3KeyPrefix=prefix,
        Text="Amazon Polly asynchronous synthesis task test.",
        VoiceId="Joanna",
    )["SynthesisTask"]
    task_id = started["TaskId"]
    assert started["TaskStatus"] in ("scheduled", "inProgress"), (
        f"expected an initial in-flight status, got {started['TaskStatus']!r}"
    )

    task = _poll_until_terminal(polly, task_id, timeout_s=180.0)
    assert task["TaskStatus"] == "completed", task.get("TaskStatusReason")
    assert task["OutputUri"], "completed task reported no OutputUri"

    objects = s3.list_objects_v2(Bucket=bucket, Prefix=prefix).get("Contents", [])
    assert len(objects) == 1, f"expected exactly 1 uploaded object, found {len(objects)}"
    key = objects[0]["Key"]
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    assert key in task["OutputUri"], (
        f"OutputUri {task['OutputUri']!r} does not reference the uploaded key {key!r}"
    )
    assert objects[0]["Size"] > 0, f"uploaded object {key} is empty"

    head = s3.head_object(Bucket=bucket, Key=key)
    assert head["ContentType"] == "audio/mpeg", (
        f"expected mp3 OutputFormat to upload as audio/mpeg, got {head['ContentType']!r}"
    )


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-polly-").lower().replace("_", "-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        # us-east-1 is the one region where CreateBucket rejects an explicit
        # LocationConstraint -- this is the S3 API's own region quirk, not a pin.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    return name


def _empty_and_delete_bucket(s3, name: str) -> None:
    try:
        objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _poll_until_terminal(polly, task_id: str, timeout_s: float = 180.0):
    deadline = time.monotonic() + timeout_s
    task = None
    while time.monotonic() < deadline:
        task = polly.get_speech_synthesis_task(TaskId=task_id)["SynthesisTask"]
        if task["TaskStatus"] in ("completed", "failed"):
            return task
        time.sleep(3.0)
    raise AssertionError(f"task {task_id} never reached a terminal state, last={task}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
