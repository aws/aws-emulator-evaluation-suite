"""start-transcription-job-without-language-params-rejected."""
from __future__ import annotations

import io
import wave

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-transcription-job-without-language-params-rejected"
GROUP = "overly-permissive"
SERVICES = ["transcribe"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartTranscriptionJob with no LanguageCode, IdentifyLanguage or IdentifyMultipleLanguages fails with
    BadRequestException and its exact message and creates no job; the same name with LanguageCode starts."""
    tx = ctx.client("transcribe")
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx, s3)
    key = "audio.wav"
    s3.put_object(Bucket=bucket, Key=key, Body=_silence_wav(1.0))

    name = ctx.unique_name("sim2real-behav-job-nolang-")
    code, message = _client_error(
        lambda: tx.start_transcription_job(TranscriptionJobName=name, Media={"MediaFileUri": f"s3://{bucket}/{key}"})
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    expected = "The language code is missing. Either add a language code or turn on language identification."
    assert message == expected, f"expected missing-language message {expected!r}, got {message!r}"

    # Effect absent: no job was created under this name. Transcribe reports a missing job
    # as BadRequestException, not the modeled NotFoundException.
    code_missing, message_missing = _client_error(lambda: tx.get_transcription_job(TranscriptionJobName=name))
    assert code_missing == "BadRequestException", f"expected BadRequestException, got {code_missing!r}"
    expected_missing = "The requested job couldn't be found. Check the job name and try your request again."
    assert message_missing == expected_missing, f"expected not-found message {expected_missing!r}, got {message_missing!r}"

    # positive control: supplying LanguageCode is accepted
    tx.start_transcription_job(
        TranscriptionJobName=name,
        LanguageCode="en-US",
        Media={"MediaFileUri": f"s3://{bucket}/{key}"},
        Tags=[{"Key": "sim2real-env", "Value": "behavioral"}],
    )
    ctx.on_cleanup(lambda: _delete_job_ignore_active(ctx, name))
    job = tx.get_transcription_job(TranscriptionJobName=name)["TranscriptionJob"]
    assert job["TranscriptionJobName"] == name


def _silence_wav(duration_s: float, sample_rate: int = 16000) -> bytes:
    n_samples = int(duration_s * sample_rate)
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(sample_rate)
        w.writeframes(b"\x00\x00" * n_samples)
    return buf.getvalue()


def _create_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("sim2real-transcribe-").lower().rstrip("-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-env", "Value": "behavioral"}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    return bucket


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _client_error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _delete_job_ignore_active(ctx, name: str) -> None:
    tx = ctx.client("transcribe")
    try:
        tx.delete_transcription_job(TranscriptionJobName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("NotFoundException", "BadRequestException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
