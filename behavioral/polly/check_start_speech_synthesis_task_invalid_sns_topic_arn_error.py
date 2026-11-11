"""start-speech-synthesis-task-invalid-sns-topic-arn-error."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "start-speech-synthesis-task-invalid-sns-topic-arn-error"
GROUP = "error-semantics"
SERVICES = ["polly"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartSpeechSynthesisTask with a malformed SnsTopicArn fails with ValidationException citing
    the snsTopicArn pattern, while the same request without SnsTopicArn starts a task."""
    polly = ctx.client("polly")
    bucket = _create_bucket(ctx)

    bad_arn = "not-an-arn-at-all"
    code, message = _error_code(
        lambda: polly.start_speech_synthesis_task(
            Engine="standard",
            OutputFormat="mp3",
            OutputS3BucketName=bucket,
            SnsTopicArn=bad_arn,
            Text="This task should never be created.",
            VoiceId="Joanna",
        )
    )
    assert code == "ValidationException", code
    expected_message = (
        f"1 validation error detected: Value '{bad_arn}' at 'snsTopicArn' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: "
        r"^arn:aws(-(cn|iso(-b)?|us-gov|eusc))?:sns:[a-z0-9_-]{1,50}:\d{12}"
        r":[a-zA-Z0-9_-]{1,251}([a-zA-Z0-9_-]{0,5}|\.fifo)$"
    )
    assert message == expected_message, message

    started = polly.start_speech_synthesis_task(
        Engine="standard",
        OutputFormat="mp3",
        OutputS3BucketName=bucket,
        Text="This task should be created successfully.",
        VoiceId="Joanna",
    )["SynthesisTask"]
    assert started["TaskStatus"] in ("scheduled", "inProgress", "completed"), started

    _poll_until(
        lambda: polly.get_speech_synthesis_task(TaskId=started["TaskId"])["SynthesisTask"],
        lambda t: t["TaskStatus"] in ("completed", "failed"),
        timeout_s=120.0,
        interval_s=3.0,
    )


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-polly-tts-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]},
    )
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
