"""start-search-job-invalid-encryption-key-arn-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-search-job-invalid-encryption-key-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["backupsearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartSearchJob rejects a syntactically malformed EncryptionKeyArn with
    ResourceNotFoundException (the KMS key it names cannot be resolved); the same request
    without EncryptionKeyArn (the positive control, in the same file) succeeds."""
    bs = ctx.client("backupsearch")

    code, message = _client_error(
        lambda: bs.start_search_job(
            Name=ctx.unique_name("sim2real-behav-searchjob-"),
            SearchScope={"BackupResourceTypes": ["S3"]},
            EncryptionKeyArn="not-an-arn-at-all",
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got code={code!r}"
    # AWS relays the KMS error text, which embeds KMS's own per-call request id: assert around it.
    assert message.startswith(
        "Invalid keyId 'not-an-arn-at-all' (Service: Kms, Status Code: 400, Request ID: "
    ), f"unexpected message: {message!r}"
    assert message.endswith(") (SDK Attempt Count: 1)"), f"unexpected message: {message!r}"

    # Positive control: identical request without the malformed field is accepted.
    started = bs.start_search_job(
        Name=ctx.unique_name("sim2real-behav-searchjob-"),
        SearchScope={"BackupResourceTypes": ["S3"]},
    )
    job_id = started["SearchJobIdentifier"]
    ctx.on_cleanup(lambda: _best_effort_stop(bs, job_id))
    assert job_id


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
