"""classification-job-cancel-is-terminal."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "classification-job-cancel-is-terminal"
GROUP = "state"
SERVICES = ["macie2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:macie")
def run(ctx) -> None:
    """Cancelling a classification job moves it to CANCELLED and the status does not revert."""
    _ensure_macie_enabled(ctx)
    bucket = _create_scratch_bucket(ctx)
    macie = ctx.client("macie2")
    job_id = _create_idle_job(ctx, bucket)

    macie.update_classification_job(jobId=job_id, jobStatus="CANCELLED")
    status = _poll_until(
        lambda: macie.describe_classification_job(jobId=job_id)["jobStatus"],
        lambda s: s == "CANCELLED",
        timeout_s=60,
    )
    assert status == "CANCELLED", f"expected UpdateClassificationJob(CANCELLED) to land, got {status!r}"

    # Freeze detector: terminal state must hold across several independent, spaced reads —
    # not just once — so a job that quietly reverts (e.g. its daily schedule re-firing) is caught.
    for _ in range(3):
        time.sleep(2)
        still = macie.describe_classification_job(jobId=job_id)["jobStatus"]
        assert still == "CANCELLED", f"expected job to remain CANCELLED, got {still!r}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _ensure_macie_enabled(ctx) -> None:
    """Enable Macie when the account has no session, and disable it again at cleanup so the
    account-wide setting ends in the state it started in."""
    from botocore.exceptions import ClientError

    macie = ctx.client("macie2")
    try:
        macie.get_macie_session()
        return
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code not in ("ResourceNotFoundException", "AccessDeniedException"):
            raise
    try:
        macie.enable_macie()
    except ClientError as exc2:
        if exc2.response["Error"]["Code"] != "ConflictException":
            raise
        return
    ctx.on_cleanup(macie.disable_macie)


def _create_scratch_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-macie-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=name))
    return name


def _create_idle_job(ctx, bucket, allow_list_ids=None) -> str:
    from botocore.exceptions import ClientError

    macie = ctx.client("macie2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    kwargs = {
        "clientToken": ctx.unique_name("sim2real-macie-job-"),
        "name": ctx.unique_name("sim2real-macie-job-"),
        "jobType": "SCHEDULED",
        "scheduleFrequency": {"dailySchedule": {}},
        "initialRun": False,
        "s3JobDefinition": {"bucketDefinitions": [{"accountId": account_id, "buckets": [bucket]}]},
    }
    if allow_list_ids:
        kwargs["allowListIds"] = allow_list_ids

    # Immediately after EnableMacie (or a fresh bucket), CreateClassificationJob can
    # transiently reject with "Macie can't create the job right now" while Macie finishes
    # provisioning/indexing. Retry with a bounded window rather than failing on this
    # eventual-consistency window.
    deadline = time.monotonic() + 180
    job_id = None
    last_exc = None
    while time.monotonic() < deadline:
        try:
            job_id = macie.create_classification_job(**kwargs)["jobId"]
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "right now" in msg:
                last_exc = exc
                time.sleep(2)
                continue
            raise
    if job_id is None:
        raise AssertionError(f"could not create classification job within deadline: {last_exc}")

    _poll_until(
        lambda: macie.describe_classification_job(jobId=job_id)["jobStatus"],
        lambda s: s == "IDLE",
        timeout_s=60,
    )
    return job_id



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
