"""resume-cancelled-job-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "resume-cancelled-job-rejected"
GROUP = "overly-permissive"
SERVICES = ["macie2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:macie")
def run(ctx) -> None:
    """UpdateClassificationJob rejects resuming a CANCELLED job; a fresh job's pause/resume still works."""
    _ensure_macie_enabled(ctx)
    bucket = _create_scratch_bucket(ctx)
    macie = ctx.client("macie2")

    cancelled_job = _create_idle_job(ctx, bucket)
    macie.update_classification_job(jobId=cancelled_job, jobStatus="CANCELLED")
    _poll_until(
        lambda: macie.describe_classification_job(jobId=cancelled_job)["jobStatus"],
        lambda s: s == "CANCELLED",
        timeout_s=60,
    )

    code, message = _error_code(lambda: macie.update_classification_job(jobId=cancelled_job, jobStatus="RUNNING"))
    assert code == "ValidationException", f"unexpected code: {code}"
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    expected_message = (
        "Input validation failed, cannot update cancelled job for job: "
        f"arn:aws:macie2:{ctx.region}:{account_id}:classification-job/{cancelled_job}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect must be absent: the job is still CANCELLED, not resumed.
    still = macie.describe_classification_job(jobId=cancelled_job)["jobStatus"]
    assert still == "CANCELLED", f"expected CANCELLED to persist, got {still}"

    # Positive control: a fresh job can legitimately pause and resume.
    control_job = _create_idle_job(ctx, bucket)
    ctx.on_cleanup(lambda: macie.update_classification_job(jobId=control_job, jobStatus="CANCELLED"))
    macie.update_classification_job(jobId=control_job, jobStatus="USER_PAUSED")
    _poll_until(
        lambda: macie.describe_classification_job(jobId=control_job)["jobStatus"],
        lambda s: s == "USER_PAUSED",
        timeout_s=60,
    )
    macie.update_classification_job(jobId=control_job, jobStatus="RUNNING")
    resumed = _poll_until(
        lambda: macie.describe_classification_job(jobId=control_job)["jobStatus"],
        lambda s: s == "IDLE",
        timeout_s=60,
    )
    assert resumed == "IDLE", f"expected fresh job to resume to IDLE, got {resumed}"


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
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
