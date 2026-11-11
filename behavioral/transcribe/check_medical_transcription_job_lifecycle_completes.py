"""medical-transcription-job-lifecycle-completes."""
from __future__ import annotations

import io
import json
import time
import wave

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "medical-transcription-job-lifecycle-completes"
GROUP = "state"
SERVICES = ["transcribe"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartMedicalTranscriptionJob drives QUEUED/IN_PROGRESS -> COMPLETED and writes
    a real transcript JSON object to the caller-specified S3 output location."""
    tx = ctx.client("transcribe")
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx, s3)
    key = "medical-audio.wav"
    s3.put_object(Bucket=bucket, Key=key, Body=_silence_wav(2.0, sample_rate=16000))

    name = ctx.unique_name("sim2real-behav-medjob-")
    output_key = "medical-output.json"
    tx.start_medical_transcription_job(
        MedicalTranscriptionJobName=name,
        LanguageCode="en-US",
        Media={"MediaFileUri": f"s3://{bucket}/{key}"},
        OutputBucketName=bucket,
        OutputKey=output_key,
        Specialty="PRIMARYCARE",
        Type="CONVERSATION",
        Tags=[{"Key": "simparity-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_medical_job_and_confirm_gone(ctx, name))

    job = _poll_medical_job(ctx, name, timeout_s=900, interval_s=10)
    assert job["TranscriptionJobStatus"] == "COMPLETED", job.get("FailureReason")

    obj = s3.get_object(Bucket=bucket, Key=output_key)
    payload = json.loads(obj["Body"].read())
    assert payload["jobName"] == name, f"expected transcript jobName {name!r}, got {payload.get('jobName')!r}"
    assert "results" in payload, f"expected a 'results' key in the transcript payload, got keys {sorted(payload)}"


# ===== helpers =====
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
    # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]})
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


def _poll_medical_job(ctx, name: str, timeout_s: float = 900.0, interval_s: float = 10.0) -> dict:
    tx = ctx.client("transcribe")
    deadline = time.monotonic() + timeout_s
    job = None
    while time.monotonic() < deadline:
        job = tx.get_medical_transcription_job(MedicalTranscriptionJobName=name)["MedicalTranscriptionJob"]
        if job["TranscriptionJobStatus"] in ("COMPLETED", "FAILED"):
            return job
        time.sleep(interval_s)
    raise AssertionError(f"medical transcription job {name} did not reach a terminal state within {timeout_s}s (last={job})")


def _delete_medical_job_and_confirm_gone(ctx, name: str) -> None:
    """Delete, retrying BadRequestException (still processing) every 2 s to a deadline, then
    confirm the read is NotFoundException; a resource already gone is clean."""
    tx = ctx.client("transcribe")
    deadline = time.monotonic() + 300
    while True:
        try:
            tx.delete_medical_transcription_job(MedicalTranscriptionJobName=name)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code != "BadRequestException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    try:
        tx.get_medical_transcription_job(MedicalTranscriptionJobName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise
        return
    raise AssertionError(f"medical transcription job {name} still readable after delete")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
