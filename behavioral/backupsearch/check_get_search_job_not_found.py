"""get-search-job-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-search-job-not-found"
GROUP = "error-semantics"
SERVICES = ["backupsearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSearchJob for a search job identifier that was never created is rejected with
    ResourceNotFoundException, while the same call against a real search job (the
    in-file positive control) succeeds."""
    bs = ctx.client("backupsearch")
    started = bs.start_search_job(
        Name=ctx.unique_name("sim2real-behav-searchjob-"),
        SearchScope={"BackupResourceTypes": ["S3"]},
    )
    job_id = started["SearchJobIdentifier"]
    ctx.on_cleanup(lambda: _best_effort_stop(bs, job_id))

    bogus_id = str(uuid.uuid4())

    code, message = _client_error(lambda: bs.get_search_job(SearchJobIdentifier=bogus_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == "Resource is not found", f"unexpected message {message!r}"

    # Positive control: the real job's own identifier still resolves cleanly.
    control = bs.get_search_job(SearchJobIdentifier=job_id)
    assert control["SearchJobIdentifier"] == job_id, (
        f"expected {job_id}, got {control.get('SearchJobIdentifier')}"
    )


def _client_error(fn):
    """Return the (code, message) of the ClientError ``fn`` raises; a success fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _best_effort_stop(bs, job_id: str) -> None:
    try:
        bs.stop_search_job(SearchJobIdentifier=job_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
