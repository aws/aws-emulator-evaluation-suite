"""list-search-job-backups-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-search-job-backups-not-found"
GROUP = "error-semantics"
SERVICES = ["backupsearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListSearchJobBackups for a search job identifier that was never created is rejected
    with ResourceNotFoundException, while the same call against a real (in-file) search
    job's identifier succeeds (the positive control)."""
    bs = ctx.client("backupsearch")
    started = bs.start_search_job(
        Name=ctx.unique_name("sim2real-behav-searchjob-"),
        SearchScope={"BackupResourceTypes": ["S3"]},
    )
    job_id = started["SearchJobIdentifier"]
    ctx.on_cleanup(lambda: _best_effort_stop(bs, job_id))

    bogus_id = str(uuid.uuid4())
    assert bogus_id != job_id

    code, message = _client_error(lambda: bs.list_search_job_backups(SearchJobIdentifier=bogus_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "Resource is not found", f"unexpected message {message!r}"

    # Positive control: the same call against the real search job succeeds.
    control = bs.list_search_job_backups(SearchJobIdentifier=job_id)
    assert isinstance(control["Results"], list), f"expected a Results list, got {control!r}"


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
