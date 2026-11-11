"""get-speech-synthesis-task-not-found-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-speech-synthesis-task-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["polly"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSpeechSynthesisTask rejects a malformed TaskId with ValidationException and a well-formed
    unknown one with SynthesisTaskNotFoundException, while a just-created task is found."""
    polly = ctx.client("polly")
    bucket = _create_bucket(ctx)

    malformed_id = "not a valid task id!!"
    code_invalid, message_invalid = _error_code(
        lambda: polly.get_speech_synthesis_task(TaskId=malformed_id)
    )
    assert code_invalid == "ValidationException", code_invalid
    expected_invalid = (
        f"1 validation error detected: Value '{malformed_id}' at 'taskId' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: ^[a-zA-Z0-9_-]{1,100}$"
    )
    assert message_invalid == expected_invalid, message_invalid

    well_formed_missing_id = "a" * 40
    code_missing, message_missing = _error_code(
        lambda: polly.get_speech_synthesis_task(TaskId=well_formed_missing_id)
    )
    assert code_missing == "SynthesisTaskNotFoundException", code_missing
    # AWS returns SynthesisTaskNotFoundException with a null message body.
    assert message_missing is None, f"expected no error message, got {message_missing!r}"

    # positive control: a real task is found by its real TaskId
    started = polly.start_speech_synthesis_task(
        OutputFormat="mp3",
        OutputS3BucketName=bucket,
        Text="Real task for the not-found control.",
        VoiceId="Joanna",
    )["SynthesisTask"]
    fetched = polly.get_speech_synthesis_task(TaskId=started["TaskId"])["SynthesisTask"]
    assert fetched["TaskId"] == started["TaskId"], (
        f"expected GetSpeechSynthesisTask to find the just-created task "
        f"{started['TaskId']!r}, got {fetched['TaskId']!r}"
    )


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-polly-nf-").lower().replace("_", "-")
    kwargs: dict[str, Any] = {"Bucket": name}
    # us-east-1 is the one region where CreateBucket rejects an explicit
    # LocationConstraint; every other region requires one.
    if ctx.region and ctx.region != "us-east-1":
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
