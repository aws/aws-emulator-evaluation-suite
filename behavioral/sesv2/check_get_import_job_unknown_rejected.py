"""get-import-job-unknown-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-import-job-unknown-rejected"
GROUP = "error-semantics"
SERVICES = ["sesv2"]
SANDBOX_MESSAGE = "Your account is still in the sandbox."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetImportJob for a never-created JobId is rejected: a sandboxed account gets the exact sandbox
    BadRequestException for any JobId; with production access it is NotFoundException, and a job just created
    reads back by its JobId.
    """
    sesv2 = ctx.client("sesv2")

    err = _error(lambda: sesv2.get_import_job(JobId="00000000-0000-0000-0000-000000000000"))
    if err.get("Code") == "BadRequestException" and err.get("Message") == SANDBOX_MESSAGE:
        # Account is still in the SES sandbox: ImportJob is gated account-wide and GetImportJob
        # deterministically rejects *any* JobId (real or fake) with this error, not NotFoundException.
        return
    # This leg runs only with SES production access; AWS does not document its not-found
    # message, so only the code is asserted.
    assert err.get("Code") == "NotFoundException", f"unexpected error for unknown JobId: {err!r}"

    s3_url = f"s3://{ctx.unique_name('sim2real-import-ctrl-')}/data.csv"
    created = sesv2.create_import_job(
        ImportDataSource={"DataFormat": "CSV", "S3Url": s3_url},
        ImportDestination={"SuppressionListDestination": {"SuppressionListImportAction": "DELETE"}},
    )
    got = sesv2.get_import_job(JobId=created["JobId"])
    assert got["JobId"] == created["JobId"], (
        f"GetImportJob returned a different JobId than CreateImportJob: got={got['JobId']!r} "
        f"created={created['JobId']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
