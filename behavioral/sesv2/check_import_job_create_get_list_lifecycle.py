"""import-job-create-get-list-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-job-create-get-list-lifecycle"
GROUP = "state-machine"
SERVICES = ["sesv2"]
SANDBOX_MESSAGE = "Your account is still in the sandbox."


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """In the SES sandbox, Create/Get/ListImportJobs all fail BadRequestException with the sandbox
    message. Otherwise the created job is visible to Get/List and reaches FAILED (no such bucket).
    """
    sesv2 = ctx.client("sesv2")
    s3_url = f"s3://{ctx.unique_name('sim2real-import-')}/data.csv"

    def _create():
        return sesv2.create_import_job(
            ImportDataSource={"DataFormat": "CSV", "S3Url": s3_url},
            ImportDestination={"SuppressionListDestination": {"SuppressionListImportAction": "DELETE"}},
        )

    try:
        resp = _create()
    except ClientError as err:
        error = err.response.get("Error", {})
        assert error.get("Code") == "BadRequestException", f"unexpected CreateImportJob error: {error!r}"
        assert error.get("Message") == SANDBOX_MESSAGE, (
            f"expected the SES sandbox refusal message from CreateImportJob, got {error.get('Message')!r}"
        )
        # The whole ImportJob surface is gated for a sandboxed account, not just CreateImportJob.
        get_err = _error(lambda: sesv2.get_import_job(JobId="00000000-0000-0000-0000-000000000000"))
        assert get_err.get("Code") == "BadRequestException", (
            f"GetImportJob should be gated the same way as CreateImportJob: {get_err!r}"
        )
        assert get_err.get("Message") == SANDBOX_MESSAGE, (
            f"expected the SES sandbox refusal message from GetImportJob, got {get_err.get('Message')!r}"
        )
        list_err = _error(lambda: sesv2.list_import_jobs())
        assert list_err.get("Code") == "BadRequestException", (
            f"ListImportJobs should be gated the same way as CreateImportJob: {list_err!r}"
        )
        assert list_err.get("Message") == SANDBOX_MESSAGE, (
            f"expected the SES sandbox refusal message from ListImportJobs, got {list_err.get('Message')!r}"
        )
        return

    job_id = resp["JobId"]
    assert job_id, f"CreateImportJob returned no JobId: {resp!r}"

    got = sesv2.get_import_job(JobId=job_id)
    assert got["JobId"] == job_id, f"GetImportJob returned JobId={got['JobId']!r}, expected {job_id!r}"
    assert got["JobStatus"] in {"CREATED", "PROCESSING", "COMPLETED", "FAILED"}, (
        f"unexpected JobStatus immediately after creation: {got['JobStatus']!r}"
    )
    assert got["ImportDataSource"]["S3Url"] == s3_url, (
        f"GetImportJob S3Url={got['ImportDataSource']['S3Url']!r}, expected {s3_url!r}"
    )

    job_ids = _list_all_import_job_ids(sesv2)
    assert job_id in job_ids, "newly created import job did not appear in ListImportJobs"

    final_status = _wait_for_terminal_status(sesv2, job_id, timeout_s=180.0)
    assert final_status == "FAILED", f"expected FAILED for a non-existent S3 bucket, got {final_status}"


def _error(fn):
    """Call fn() and return its botocore Error dict; raise if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _list_all_import_job_ids(sesv2) -> set[str]:

    ids: set[str] = set()
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = sesv2.list_import_jobs(**kwargs)
        for job in resp.get("ImportJobs", []):
            ids.add(job["JobId"])
        token = resp.get("NextToken")
        if not token:
            break
    return ids


def _wait_for_terminal_status(sesv2, job_id: str, timeout_s: float = 180.0, interval_s: float = 5.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = sesv2.get_import_job(JobId=job_id)["JobStatus"]
        if status in ("COMPLETED", "FAILED", "CANCELLED"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"import job {job_id} never reached a terminal status within {timeout_s}s (last={status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
