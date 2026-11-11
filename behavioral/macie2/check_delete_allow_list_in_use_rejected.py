"""delete-allow-list-in-use-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-allow-list-in-use-rejected"
GROUP = "overly-permissive"
SERVICES = ["macie2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:macie")
def run(ctx) -> None:
    """DeleteAllowList rejects deletion of a list referenced by a non-terminal job unless ignoreJobChecks=true."""
    _ensure_macie_enabled(ctx)
    bucket = _create_scratch_bucket(ctx)
    macie = ctx.client("macie2")

    allow_list_name = ctx.unique_name("sim2real-macie-al-")
    allow_list_criteria = {"regex": ".+"}
    allow_list_id = macie.create_allow_list(
        name=allow_list_name,
        clientToken=ctx.unique_name("sim2real-macie-al-tok-"),
        criteria=allow_list_criteria,
        tags={"sim2real-behav": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: _delete_allow_list_ignore_missing(macie, allow_list_id))

    job_id = _create_idle_job(ctx, bucket, allow_list_ids=[allow_list_id])
    ctx.on_cleanup(lambda: macie.update_classification_job(jobId=job_id, jobStatus="CANCELLED"))

    error = _client_error(lambda: macie.delete_allow_list(id=allow_list_id, ignoreJobChecks="false"))
    assert error["Code"] == "ValidationException", f"expected ValidationException, got {error['Code']!r}"
    assert error["Message"] == (
        "The allow list can't be deleted. 1 jobs are configured to use the list and those jobs "
        "have a status other than Complete or Cancelled."
    ), f"unexpected message: {error['Message']!r}"

    # Effect must be absent: the allow list is still there.
    still_there = macie.get_allow_list(id=allow_list_id)
    assert still_there["id"] == allow_list_id, (
        f"delete was rejected but allow list {allow_list_id!r} is missing from an independent read"
    )

    # Positive control: forcing the override deletes it.
    macie.delete_allow_list(id=allow_list_id, ignoreJobChecks="true")
    gone = _client_error(lambda: macie.get_allow_list(id=allow_list_id))
    assert gone["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading the deleted allow list, got {gone['Code']!r}"
    )
    assert gone["Message"] == _ALLOW_LIST_NOT_FOUND, f"unexpected message: {gone['Message']!r}"

    # Deletes prove gone AND unusable: a mutation on the now-dead id must also fail, not just a read.
    update = _client_error(
        lambda: macie.update_allow_list(
            id=allow_list_id, name=allow_list_name, criteria=allow_list_criteria
        )
    )
    assert update["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException updating the deleted allow list, got {update['Code']!r}"
    )
    assert update["Message"] == _ALLOW_LIST_NOT_FOUND, f"unexpected message: {update['Message']!r}"


_ALLOW_LIST_NOT_FOUND = (
    "Input validation failed. The request specifies an allow list that does not exist."
)


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises rather than returning
    a falsy sentinel."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED with {result!r}")


def _delete_allow_list_ignore_missing(macie, allow_list_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        macie.delete_allow_list(id=allow_list_id, ignoreJobChecks="true")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
    from botocore.exceptions import ClientError

    macie = ctx.client("macie2")
    try:
        macie.get_macie_session()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code not in ("ResourceNotFoundException", "AccessDeniedException"):
            raise
        try:
            macie.enable_macie()
        except ClientError as exc2:
            if exc2.response["Error"]["Code"] != "ConflictException":
                raise


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
    macie = ctx.client("macie2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    kwargs = {
        "clientToken": ctx.unique_name("sim2real-macie-job-"),
        "name": ctx.unique_name("sim2real-macie-job-"),
        "jobType": "SCHEDULED",
        "scheduleFrequency": {"dailySchedule": {}},
        "initialRun": False,
        "s3JobDefinition": {"bucketDefinitions": [{"accountId": account_id, "buckets": [bucket]}]},
        "tags": {"sim2real-behav": CHECK},
    }
    if allow_list_ids:
        kwargs["allowListIds"] = allow_list_ids
    job_id = macie.create_classification_job(**kwargs)["jobId"]
    _poll_until(
        lambda: macie.describe_classification_job(jobId=job_id)["jobStatus"],
        lambda s: s == "IDLE",
        timeout_s=60,
    )
    return job_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
