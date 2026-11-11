"""list-tags-for-resource-not-found."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-tags-for-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["backupsearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource on a well-formed but nonexistent search-job ARN is rejected with
    NotFoundException, while the same call on a real search job's ARN succeeds."""
    bs = ctx.client("backupsearch")
    started = bs.start_search_job(
        Name=ctx.unique_name("sim2real-behav-searchjob-"),
        SearchScope={"BackupResourceTypes": ["S3"]},
    )
    job_id = started["SearchJobIdentifier"]
    real_arn = started["SearchJobArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(bs, job_id))

    bogus_arn = real_arn.rsplit("/", 1)[0] + "/00000000-0000-0000-0000-000000000000"
    assert bogus_arn != real_arn

    code, message = _client_error(lambda: bs.list_tags_for_resource(ResourceArn=bogus_arn))
    assert code == "NotFoundException", f"expected NotFoundException, got code={code!r}"
    assert message == "Resource was not found", f"unexpected message {message!r}"

    # Positive control: the real resource's own ARN still resolves cleanly.
    control = bs.list_tags_for_resource(ResourceArn=real_arn)
    assert control.get("Tags", {}) == {}


def _client_error(fn):
    """Return the (code, message) of the ClientError ``fn`` raises; a success fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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
