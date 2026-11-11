"""medical-vocabulary-lifecycle-pending-to-ready."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "medical-vocabulary-lifecycle-pending-to-ready"
GROUP = "state"
SERVICES = ["transcribe"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateMedicalVocabulary (file-based, no Phrases option) starts PENDING and
    transitions to READY once Transcribe Medical processes the S3 vocabulary file."""
    tx = ctx.client("transcribe")
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx, s3)
    key = "medical-vocab.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"Ibuprofen\nAcetaminophen\nTachycardia\n")

    name = ctx.unique_name("sim2real-behav-medvocab-")
    create_resp = tx.create_medical_vocabulary(
        VocabularyName=name,
        LanguageCode="en-US",
        VocabularyFileUri=f"s3://{bucket}/{key}",
        Tags=[{"Key": "simparity-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_medical_vocabulary_and_confirm_gone(ctx, name))
    assert create_resp["VocabularyState"] == "PENDING", f"expected PENDING at create, got {create_resp['VocabularyState']}"

    final_state = _poll_medical_vocabulary_state(ctx, name, timeout_s=300, interval_s=10)
    assert final_state == "READY", f"expected READY, got {final_state}"


# ===== helpers =====
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


def _poll_medical_vocabulary_state(ctx, name: str, timeout_s: float = 300.0, interval_s: float = 10.0) -> str:
    tx = ctx.client("transcribe")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = tx.get_medical_vocabulary(VocabularyName=name)["VocabularyState"]
        if state != "PENDING":
            return state
        time.sleep(interval_s)
    raise AssertionError(f"medical vocabulary {name} stayed PENDING for {timeout_s}s (last={state})")


def _delete_medical_vocabulary_and_confirm_gone(ctx, name: str) -> None:
    """Delete, retrying BadRequestException (still processing) every 2 s to a deadline, then
    confirm the read is NotFoundException; a resource already gone is clean."""
    tx = ctx.client("transcribe")
    deadline = time.monotonic() + 300
    while True:
        try:
            tx.delete_medical_vocabulary(VocabularyName=name)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code != "BadRequestException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    try:
        tx.get_medical_vocabulary(VocabularyName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise
        return
    raise AssertionError(f"medical vocabulary {name} still readable after delete")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
