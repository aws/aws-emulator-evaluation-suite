"""transcription-job-lifecycle-completes."""
from __future__ import annotations

import io
import json
import time
import urllib.request
import wave

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "transcription-job-lifecycle-completes"
GROUP = "state"
SERVICES = ["transcribe"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """StartTranscriptionJob returns QUEUED or IN_PROGRESS, the job reaches COMPLETED with one transcript document
    naming this job, and after DeleteTranscriptionJob GetTranscriptionJob fails with BadRequestException and the
    exact not-found message."""
    tx = ctx.client("transcribe")
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx, s3)
    key = "sim2real-audio.wav"
    s3.put_object(Bucket=bucket, Key=key, Body=_silence_wav(2.0))

    name = ctx.unique_name("sim2real-behav-job-")
    start = tx.start_transcription_job(
        TranscriptionJobName=name,
        LanguageCode="en-US",
        Media={"MediaFileUri": f"s3://{bucket}/{key}"},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    start_status = start["TranscriptionJob"]["TranscriptionJobStatus"]
    assert start_status in ("QUEUED", "IN_PROGRESS"), (
        f"expected a freshly started job to be non-terminal, got {start_status!r}"
    )
    ctx.on_cleanup(lambda: _delete_job_ignore_active(ctx, name))

    job = _poll_transcription_job(ctx, name, timeout_s=900, interval_s=10)
    assert job["TranscriptionJobStatus"] == "COMPLETED", job.get("FailureReason")

    uri = job["Transcript"]["TranscriptFileUri"]
    with urllib.request.urlopen(_routed_request(ctx, uri), timeout=30) as resp:
        payload = json.loads(resp.read())
    assert payload["jobName"] == name, f"transcript document names job {payload.get('jobName')!r}, not {name!r}"
    assert payload.get("status") == "COMPLETED", f"transcript document status {payload.get('status')!r}"
    transcripts = payload["results"]["transcripts"]
    assert len(transcripts) == 1, f"expected exactly one transcript alternative, got {transcripts!r}"
    assert isinstance(transcripts[0]["transcript"], str), transcripts[0]
    assert isinstance(payload["results"]["items"], list), payload["results"]

    tx.delete_transcription_job(TranscriptionJobName=name)
    try:
        tx.get_transcription_job(TranscriptionJobName=name)
        raise AssertionError(f"transcription job {name} is still readable after DeleteTranscriptionJob")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "BadRequestException", f"expected BadRequestException after delete, got {code!r}"
        message = e.response["Error"].get("Message")
        expected = "The requested job couldn't be found. Check the job name and try your request again."
        assert message == expected, f"expected not-found message {expected!r}, got {message!r}"


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
    # S3 quirk, not a region pin: CreateBucket rejects an explicit LocationConstraint
    # of us-east-1 (its own default region), so the constraint is only sent for others.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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
