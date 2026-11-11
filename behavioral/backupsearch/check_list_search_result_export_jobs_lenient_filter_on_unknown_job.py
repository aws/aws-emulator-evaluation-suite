"""list-search-result-export-jobs-lenient-filter-on-unknown-job."""
from __future__ import annotations

import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-search-result-export-jobs-lenient-filter-on-unknown-job"
GROUP = "error-semantics"
SERVICES = ["backupsearch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSearchResultExportJobs filtered by a well-formed but nonexistent SearchJobIdentifier
    returns an empty page rather than ResourceNotFoundException, the same as filtering by a real
    search job with no export jobs."""
    bs = ctx.client("backupsearch")
    started = bs.start_search_job(
        Name=ctx.unique_name("sim2real-behav-searchjob-"),
        SearchScope={"BackupResourceTypes": ["S3"]},
        Tags={"sim2real-check": CHECK},
    )
    job_id = started["SearchJobIdentifier"]
    ctx.on_cleanup(lambda: _best_effort_stop(bs, job_id))

    bogus_id = str(uuid.uuid4())
    result, code = _error_code_or_result(
        lambda: bs.list_search_result_export_jobs(SearchJobIdentifier=bogus_id)
    )
    assert code is None, f"expected no error (lenient filter), got code={code}"
    assert result["ExportJobs"] == [], f"expected empty page for unknown job id, got {result!r}"

    # Positive control: filtering by the real search job identifier also returns an empty page.
    control = bs.list_search_result_export_jobs(SearchJobIdentifier=job_id)
    assert control["ExportJobs"] == [], (
        f"expected empty page for real (in-file) job id with no export jobs, got {control!r}"
    )


def _error_code_or_result(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
        return result, None
    except ClientError as err:
        return None, err.response["Error"]["Code"]


def _best_effort_stop(bs, job_id: str) -> None:
    # A job already in a terminal state answers StopSearchJob with ConflictException: nothing to stop.
    try:
        bs.stop_search_job(SearchJobIdentifier=job_id)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "ResourceNotFoundException":
            return
        terminal = ("COMPLETED", "FAILED", "STOPPED", "STOPPING")
        if code == "ConflictException" and bs.get_search_job(SearchJobIdentifier=job_id)["Status"] in terminal:
            return
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

