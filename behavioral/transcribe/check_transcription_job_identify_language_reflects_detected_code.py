"""transcription-job-identify-language-reflects-detected-code."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transcription-job-identify-language-reflects-detected-code"
GROUP = "data-plane"
SERVICES = ["transcribe"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """With IdentifyLanguage=True, jobs over English and French Polly speech complete with LanguageCode en-US and
    fr-FR respectively, each with IdentifiedLanguageScore above 0.5."""
    polly = ctx.client("polly")
    s3 = ctx.client("s3")
    tx = ctx.client("transcribe")

    bucket = _create_bucket(ctx, s3)
    language_options = ["en-US", "es-ES", "fr-FR"]

    en_audio = polly.synthesize_speech(
        Text="This is a test of automatic language identification.", OutputFormat="mp3", VoiceId="Joanna"
    )["AudioStream"].read()
    fr_audio = polly.synthesize_speech(
        Text="Ceci est un test d'identification automatique de la langue.", OutputFormat="mp3", VoiceId="Lea"
    )["AudioStream"].read()
    s3.put_object(Bucket=bucket, Key="speech-en.mp3", Body=en_audio, ContentType="audio/mpeg")
    s3.put_object(Bucket=bucket, Key="speech-fr.mp3", Body=fr_audio, ContentType="audio/mpeg")

    en_name = ctx.unique_name("sim2real-behav-langid-en-")
    fr_name = ctx.unique_name("sim2real-behav-langid-fr-")
    for name, key in ((en_name, "speech-en.mp3"), (fr_name, "speech-fr.mp3")):
        tx.start_transcription_job(
            TranscriptionJobName=name,
            IdentifyLanguage=True,
            LanguageOptions=language_options,
            MediaFormat="mp3",
            Media={"MediaFileUri": f"s3://{bucket}/{key}"},
        )
        ctx.on_cleanup(lambda name=name: _delete_job_ignore_active(ctx, name))

    jobs = _poll_transcription_jobs(ctx, [en_name, fr_name], timeout_s=900, interval_s=10)
    en_job, fr_job = jobs[en_name], jobs[fr_name]

    assert en_job["TranscriptionJobStatus"] == "COMPLETED", en_job.get("FailureReason")
    assert fr_job["TranscriptionJobStatus"] == "COMPLETED", fr_job.get("FailureReason")
    assert en_job["LanguageCode"] == "en-US", f"expected en-US to be identified, got {en_job.get('LanguageCode')}"
    assert fr_job["LanguageCode"] == "fr-FR", f"expected fr-FR to be identified, got {fr_job.get('LanguageCode')}"
    assert en_job["IdentifiedLanguageScore"] > 0.5, en_job.get("IdentifiedLanguageScore")
    assert fr_job["IdentifiedLanguageScore"] > 0.5, fr_job.get("IdentifiedLanguageScore")


def _create_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("sim2real-transcribe-").lower().rstrip("-")
    kwargs = {"Bucket": bucket}
    # us-east-1 is the one region S3 rejects as an explicit LocationConstraint.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
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


def _poll_transcription_jobs(
    ctx, names: list[str], timeout_s: float = 900.0, interval_s: float = 10.0
) -> dict[str, dict]:
    tx = ctx.client("transcribe")
    deadline = time.monotonic() + timeout_s
    done: dict[str, dict] = {}
    last: dict[str, dict] = {}
    while time.monotonic() < deadline and len(done) < len(names):
        for name in names:
            if name in done:
                continue
            job = tx.get_transcription_job(TranscriptionJobName=name)["TranscriptionJob"]
            last[name] = job
            if job["TranscriptionJobStatus"] in ("COMPLETED", "FAILED"):
                done[name] = job
        if len(done) < len(names):
            time.sleep(interval_s)
    missing = [n for n in names if n not in done]
    if missing:
        raise AssertionError(
            f"transcription job(s) {missing} did not reach a terminal state within {timeout_s}s "
            f"(last={ {n: last.get(n) for n in missing} })"
        )
    return done


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
