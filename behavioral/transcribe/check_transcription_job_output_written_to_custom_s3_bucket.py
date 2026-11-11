"""transcription-job-output-written-to-custom-s3-bucket."""
from __future__ import annotations

import io
import json
import time
import wave

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transcription-job-output-written-to-custom-s3-bucket"
GROUP = "data-plane"
SERVICES = ["transcribe"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """OutputBucketName/OutputKey must cause the completed job's transcript to be
    written as a real object at that exact bucket/key -- not just referenced by URI."""
    tx = ctx.client("transcribe")
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx, s3)
    input_key = "input.wav"
    s3.put_object(Bucket=bucket, Key=input_key, Body=_silence_wav(1.5))

    name = ctx.unique_name("sim2real-behav-outbucket-")
    output_key = "results/transcript-output.json"
    tx.start_transcription_job(
        TranscriptionJobName=name,
        LanguageCode="en-US",
        Media={"MediaFileUri": f"s3://{bucket}/{input_key}"},
        OutputBucketName=bucket,
        OutputKey=output_key,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_job_ignore_active(ctx, name))

    job = _poll_transcription_job(ctx, name, timeout_s=900, interval_s=10)
    assert job["TranscriptionJobStatus"] == "COMPLETED", job.get("FailureReason")

    obj = s3.get_object(Bucket=bucket, Key=output_key)
    payload = json.loads(obj["Body"].read())
    assert payload["jobName"] == name, f"expected jobName {name!r}, got {payload.get('jobName')!r}"
    assert "results" in payload, f"custom-bucket transcript output missing 'results': {sorted(payload)}"
    transcripts = payload["results"]["transcripts"]
    assert isinstance(transcripts, list), f"expected a transcripts list, got {transcripts!r}"


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
    # us-east-1 is the one region CreateBucket rejects a LocationConstraint for; every
    # other region requires one. ctx.region is us-west-2 in practice, so this is a
    # correctness branch, not a region pin.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
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
