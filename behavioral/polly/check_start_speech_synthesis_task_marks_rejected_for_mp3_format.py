"""start-speech-synthesis-task-marks-rejected-for-mp3-format."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "start-speech-synthesis-task-marks-rejected-for-mp3-format"
GROUP = "overly-permissive"
SERVICES = ["polly"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartSpeechSynthesisTask with SpeechMarkTypes and OutputFormat=mp3 fails with
    MarksNotSupportedForFormatException and writes nothing to the bucket, while OutputFormat=json
    is accepted and the task completes and writes its output."""
    polly = ctx.client("polly")
    bucket = _create_bucket(ctx)

    code, message = _error(
        lambda: polly.start_speech_synthesis_task(
            Engine="standard",
            OutputFormat="mp3",
            OutputS3BucketName=bucket,
            SpeechMarkTypes=["sentence"],
            Text="This task should never be created.",
            VoiceId="Joanna",
        )
    )
    assert code == "MarksNotSupportedForFormatException", code
    assert message == "Speech marks are not supported for this format", message

    s3 = ctx.client("s3")
    rejected_objects = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
    assert rejected_objects == [], (
        f"rejected StartSpeechSynthesisTask must create no task and write no output, "
        f"found {rejected_objects!r}"
    )

    started = polly.start_speech_synthesis_task(
        Engine="standard",
        OutputFormat="json",
        OutputS3BucketName=bucket,
        SpeechMarkTypes=["sentence"],
        Text="This task should be created successfully.",
        VoiceId="Joanna",
    )["SynthesisTask"]
    assert started["TaskStatus"] in ("scheduled", "inProgress", "completed"), started

    final = _poll_until(
        lambda: polly.get_speech_synthesis_task(TaskId=started["TaskId"])["SynthesisTask"],
        lambda t: t["TaskStatus"] in ("completed", "failed"),
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert final["TaskStatus"] == "completed", final.get("TaskStatusReason")

    completed_objects = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
    assert completed_objects, (
        f"completed StartSpeechSynthesisTask must write its output to the destination "
        f"bucket {bucket!r}, found none"
    )


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-polly-tts-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
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


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded instead: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
