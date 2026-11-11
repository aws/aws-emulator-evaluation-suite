"""get-speech-synthesis-task-invalid-id-format-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "get-speech-synthesis-task-invalid-id-format-rejected"
GROUP = "overly-permissive"
SERVICES = ["polly"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSpeechSynthesisTask rejects a TaskId outside ^[a-zA-Z0-9_-]{1,100}$ with
    ValidationException, a well-formed unknown TaskId with SynthesisTaskNotFoundException, and
    finds a just-created task."""
    polly = ctx.client("polly")

    malformed_id = "bad id! not/valid"
    malformed_code, malformed_message = _error_code(
        lambda: polly.get_speech_synthesis_task(TaskId=malformed_id)
    )
    assert malformed_code == "ValidationException", malformed_code
    expected_message = (
        f"1 validation error detected: Value '{malformed_id}' at 'taskId' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: ^[a-zA-Z0-9_-]{1,100}$"
    )
    assert malformed_message == expected_message, malformed_message

    # A well-formed id that simply does not exist hits the *different* not-found
    # validation layer, proving the format check didn't just reject everything.
    well_formed_unknown_id = "a" * 40
    unknown_code, unknown_message = _error_code(
        lambda: polly.get_speech_synthesis_task(TaskId=well_formed_unknown_id)
    )
    assert unknown_code == "SynthesisTaskNotFoundException", unknown_code
    # AWS returns SynthesisTaskNotFoundException with a null message body.
    assert unknown_message is None, f"expected no error message, got {unknown_message!r}"

    # Positive control: a real task, just created, is found by its real TaskId -- without
    # this leg, a target that always fails GetSpeechSynthesisTask (varying only the error code
    # by TaskId shape, and never actually persisting or looking up a task) would still pass
    # both assertions above.
    bucket = _create_bucket(ctx)
    started = polly.start_speech_synthesis_task(
        OutputFormat="mp3",
        OutputS3BucketName=bucket,
        Text="Positive control for GetSpeechSynthesisTask's validation layering.",
        VoiceId="Joanna",
    )["SynthesisTask"]
    fetched = polly.get_speech_synthesis_task(TaskId=started["TaskId"])["SynthesisTask"]
    assert fetched["TaskId"] == started["TaskId"], (started["TaskId"], fetched["TaskId"])


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-polly-idfmt-").lower().replace("_", "-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    return name


def _empty_and_delete_bucket(s3, name: str) -> None:
    objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
    for obj in objs:
        s3.delete_object(Bucket=name, Key=obj["Key"])
    s3.delete_bucket(Bucket=name)


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
