"""start-speech-synthesis-task-text-length-exceeded-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-speech-synthesis-task-text-length-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["polly"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartSpeechSynthesisTask rejects text past its 100,000-character limit with
    TextLengthExceededException and creates no task, while a short text starts a task."""
    polly = ctx.client("polly")
    bucket = _create_bucket(ctx)

    tasks_before_negative = {t["TaskId"] for t in _list_all(polly)}

    too_long = "a" * 100_001
    code, message = _error_code(
        lambda: polly.start_speech_synthesis_task(
            OutputFormat="mp3",
            OutputS3BucketName=bucket,
            Text=too_long,
            VoiceId="Joanna",
        )
    )
    assert code == "TextLengthExceededException", f"expected TextLengthExceededException, got {code!r}"
    assert message == "Maximum text length has been exceeded", message

    # effect absent: the rejected call created no task (independent read, not the failed call's own response)
    tasks_after_negative = {t["TaskId"] for t in _list_all(polly)}
    leaked = tasks_after_negative - tasks_before_negative
    assert not leaked, f"expected no task created by the rejected call, found {leaked}"

    # positive control: a short text starts a real task
    started = polly.start_speech_synthesis_task(
        OutputFormat="mp3",
        OutputS3BucketName=bucket,
        Text="Short text control.",
        VoiceId="Joanna",
    )["SynthesisTask"]
    task_id = started["TaskId"]
    assert task_id not in tasks_after_negative, f"expected a new TaskId, got pre-existing {task_id}"

    # terminal read is independent of the mutating call: GetSpeechSynthesisTask, not StartSpeechSynthesisTask's own response
    fetched = polly.get_speech_synthesis_task(TaskId=task_id)["SynthesisTask"]
    assert fetched["TaskId"] == task_id, f"expected TaskId {task_id}, got {fetched['TaskId']!r}"
    assert fetched["TaskStatus"] in ("scheduled", "inProgress", "completed"), (
        f"expected scheduled/inProgress/completed, got {fetched['TaskStatus']!r}"
    )


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-polly-txtlen-").lower().replace("_", "-")
    kwargs: dict[str, Any] = {"Bucket": name}
    # us-east-1 is the one region S3's CreateBucket rejects a LocationConstraint for; not a region pin.
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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


def _list_all(polly):
    out = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = polly.list_speech_synthesis_tasks(**kwargs)
        out.extend(resp["SynthesisTasks"])
        token = resp.get("NextToken")
        if not token:
            return out


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
