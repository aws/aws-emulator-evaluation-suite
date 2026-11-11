"""stop-search-job-not-found."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "stop-search-job-not-found"
GROUP = "error-semantics"
SERVICES = ["backupsearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopSearchJob on a never-created search job identifier is rejected with
    ResourceNotFoundException, while on a real in-flight search job it succeeds and GetSearchJob
    then reports STOPPED."""
    bs = ctx.client("backupsearch")
    bogus_id = str(uuid.uuid4())

    code, message = _client_error(lambda: bs.stop_search_job(SearchJobIdentifier=bogus_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "Resource is not found", f"unexpected message {message!r}"

    # Positive control: the same operation on a real search job succeeds and actually stops it,
    # so the negative above cannot be explained by a target that rejects every StopSearchJob call.
    started = bs.start_search_job(
        Name=ctx.unique_name("sim2real-behav-searchjob-"),
        SearchScope={"BackupResourceTypes": ["S3"]},
    )
    job_id = started["SearchJobIdentifier"]
    ctx.on_cleanup(lambda: _best_effort_stop(bs, job_id))

    bs.stop_search_job(SearchJobIdentifier=job_id)
    stopped = _poll_until(
        lambda: bs.get_search_job(SearchJobIdentifier=job_id),
        lambda r: r["Status"] in ("STOPPED", "COMPLETED", "FAILED"),
        timeout_s=120.0,
        interval_s=2.0,
    )
    assert stopped["Status"] == "STOPPED", f"positive control did not reach STOPPED: {stopped}"


def _client_error(fn):
    """Return the (code, message) of the ClientError ``fn`` raises; a success fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _best_effort_stop(bs, job_id: str) -> None:
    try:
        bs.stop_search_job(SearchJobIdentifier=job_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
