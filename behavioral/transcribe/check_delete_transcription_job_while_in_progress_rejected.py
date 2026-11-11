"""delete-transcription-job-while-in-progress-rejected."""
from __future__ import annotations

import io
import time
import wave

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-transcription-job-while-in-progress-rejected"
GROUP = "overly-permissive"
SERVICES = ["transcribe"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTranscriptionJob on a QUEUED or IN_PROGRESS job is refused with BadRequestException and its exact message
    and the job still exists; once COMPLETED it deletes, and GetTranscriptionJob then fails with the exact not-found
    message."""
    tx = ctx.client("transcribe")
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx, s3)
    key = "audio.wav"
    s3.put_object(Bucket=bucket, Key=key, Body=_silence_wav(3.0))

    name = ctx.unique_name("sim2real-behav-job-active-")
    tx.start_transcription_job(
        TranscriptionJobName=name,
        LanguageCode="en-US",
        Media={"MediaFileUri": f"s3://{bucket}/{key}"},
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_job_ignore_active(ctx, name))

    status = tx.get_transcription_job(TranscriptionJobName=name)["TranscriptionJob"]["TranscriptionJobStatus"]
    if status in ("COMPLETED", "FAILED"):
        raise AssertionError(f"job reached terminal state ({status}) before the non-terminal delete attempt could run")

    code, message = _client_error(lambda: tx.delete_transcription_job(TranscriptionJobName=name))
    assert code == "BadRequestException", f"expected BadRequestException rejecting delete of a non-terminal ({status}) job, got {code}"
    expected = "The job couldn't be deleted. Make sure it exists and isn't pending."
    assert message == expected, f"expected active-job delete message {expected!r}, got {message!r}"

    # effect absent: the job is still there, unaffected by the rejected delete
    still_there = tx.get_transcription_job(TranscriptionJobName=name)["TranscriptionJob"]
    assert still_there["TranscriptionJobName"] == name, (
        f"expected the job to still exist after the rejected delete, got {still_there!r}"
    )

    # positive control: once terminal, delete succeeds for real
    job = _poll_transcription_job(ctx, name, timeout_s=900, interval_s=10)
    assert job["TranscriptionJobStatus"] == "COMPLETED", job.get("FailureReason")
    tx.delete_transcription_job(TranscriptionJobName=name)
    # Transcribe reports a deleted/unknown job name as BadRequestException, not the
    # NotFoundException GetTranscriptionJob also models.
    code_after, message_after = _client_error(lambda: tx.get_transcription_job(TranscriptionJobName=name))
    assert code_after == "BadRequestException", f"expected BadRequestException reading the deleted job, got {code_after}"
    expected_after = "The requested job couldn't be found. Check the job name and try your request again."
    assert message_after == expected_after, f"expected not-found message {expected_after!r}, got {message_after!r}"


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
        # us-east-1 rejects create_bucket if given an explicit LocationConstraint for itself.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
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
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_transcription_job(ctx, name: str, timeout_s: float = 900.0, interval_s: float = 10.0) -> dict:
    tx = ctx.client("transcribe")
    deadline = time.monotonic() + timeout_s
    job = None
    while time.monotonic() < deadline:
        job = tx.get_transcription_job(TranscriptionJobName=name)["TranscriptionJob"]
        if job["TranscriptionJobStatus"] in ("COMPLETED", "FAILED"):
            return job
        time.sleep(interval_s)
    raise AssertionError(f"transcription job {name} did not reach a terminal state within {timeout_s}s (last={job})")


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
