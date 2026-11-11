"""native-speech-to-text-round-trip-via-polly."""
from __future__ import annotations

import json
import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "native-speech-to-text-round-trip-via-polly"
GROUP = "data-plane"
SERVICES = ["transcribe"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A transcription job over Polly-synthesized speech completes and its transcript contains at least 60% of the
    spoken words, so a backend that completes with an empty or wrong transcript fails."""
    polly = ctx.client("polly")
    s3 = ctx.client("s3")
    tx = ctx.client("transcribe")

    text = "The quick brown fox jumps over the lazy dog"
    audio = polly.synthesize_speech(Text=text, OutputFormat="mp3", VoiceId="Joanna")["AudioStream"].read()
    assert len(audio) > 1000, "Polly returned suspiciously little audio data"

    bucket = _create_bucket(ctx, s3)
    key = "sim2real-speech.mp3"
    s3.put_object(Bucket=bucket, Key=key, Body=audio, ContentType="audio/mpeg")

    job_name = ctx.unique_name("sim2real-behav-asr-")
    tx.start_transcription_job(
        TranscriptionJobName=job_name,
        LanguageCode="en-US",
        MediaFormat="mp3",
        Media={"MediaFileUri": f"s3://{bucket}/{key}"},
        Tags=[{"Key": "sim2real-env", "Value": "behavioral"}],
    )
    ctx.on_cleanup(lambda: _delete_job_ignore_active(ctx, job_name))

    job = _poll_transcription_job(ctx, job_name, timeout_s=900, interval_s=10)
    assert job["TranscriptionJobStatus"] == "COMPLETED", (
        f"expected COMPLETED, got {job['TranscriptionJobStatus']}: {job.get('FailureReason')}"
    )

    uri = job["Transcript"]["TranscriptFileUri"]
    with urllib.request.urlopen(_routed_request(ctx, uri), timeout=30) as resp:
        payload = json.loads(resp.read())
    transcript_text = payload["results"]["transcripts"][0]["transcript"].strip().lower()

    original_words = {w.strip(".,!?").lower() for w in text.split()}
    matched = sum(1 for w in original_words if w in transcript_text)
    assert matched >= len(original_words) * 0.6, (
        f"transcript {transcript_text!r} does not resemble the synthesized speech {text!r} "
        f"(matched {matched}/{len(original_words)} words)"
    )


def _create_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("sim2real-transcribe-").lower().rstrip("-")
    kwargs = {"Bucket": bucket}
    # us-east-1 rejects CreateBucketConfiguration/LocationConstraint outright; every other region requires it.
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
