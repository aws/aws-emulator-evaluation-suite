"""start-speech-synthesis-task-lexicon-not-found-error."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "start-speech-synthesis-task-lexicon-not-found-error"
GROUP = "error-semantics"
SERVICES = ["polly"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartSpeechSynthesisTask referencing a lexicon name that was never stored is rejected
    synchronously with LexiconNotFoundException and creates no task, while the identical
    request without the bogus lexicon reference succeeds and actually completes."""
    polly = ctx.client("polly")
    bucket = _create_bucket(ctx)
    missing_lexicon = _lexicon_name(ctx, "miss")

    code, message = _error_code(
        lambda: polly.start_speech_synthesis_task(
            Engine="standard",
            OutputFormat="mp3",
            OutputS3BucketName=bucket,
            Text="This task should never be created.",
            VoiceId="Joanna",
            LexiconNames=[missing_lexicon],
        )
    )
    assert code == "LexiconNotFoundException", code
    assert message == "Lexicon not found", message

    task_id = polly.start_speech_synthesis_task(
        Engine="standard",
        OutputFormat="mp3",
        OutputS3BucketName=bucket,
        Text="This task should be created successfully.",
        VoiceId="Joanna",
    )["SynthesisTask"]["TaskId"]

    # terminal read is independent of the mutating call: GetSpeechSynthesisTask, not the
    # StartSpeechSynthesisTask response.
    final = _poll_until(
        lambda: polly.get_speech_synthesis_task(TaskId=task_id)["SynthesisTask"],
        lambda t: t["TaskStatus"] in ("completed", "failed"),
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert final["TaskStatus"] == "completed", final.get("TaskStatusReason")


def _lexicon_name(ctx, tag: str) -> str:
    # Lexicon names are [0-9A-Za-z]{1,20}; "sim2real" (8) + the 12-hex unique suffix is exactly 20,
    # so `tag` no longer fits without truncating the random suffix. It stays a call-site label only.
    raw = ctx.unique_name("sim2real")
    return "".join(ch for ch in raw if ch.isalnum())[:20]


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-polly-tts-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "polly-tts"}]})
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
