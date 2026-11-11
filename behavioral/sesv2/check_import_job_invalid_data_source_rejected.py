"""import-job-invalid-data-source-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-job-invalid-data-source-rejected"
GROUP = "error-semantics"
SERVICES = ["sesv2"]
SANDBOX_MESSAGE = "Your account is still in the sandbox."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateImportJob with a non-s3:// S3Url fails BadRequestException with the regex message.
    A well-formed request is stored and readable via GetImportJob unless the account is sandboxed.
    """
    sesv2 = ctx.client("sesv2")
    bad_url = "not-a-valid-s3-url"

    err = _error(
        lambda: sesv2.create_import_job(
            ImportDataSource={"DataFormat": "CSV", "S3Url": bad_url},
            ImportDestination={"SuppressionListDestination": {"SuppressionListImportAction": "DELETE"}},
        )
    )
    assert err.get("Code") == "BadRequestException", f"expected BadRequestException for malformed S3Url, got {err!r}"
    expected = (
        "1 validation error detected: Value at 'importDataSource.s3Url' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: "
        "^s3:\\/\\/([^\\/]+)\\/(.*?([^\\/]+)\\/?)$"
    )
    assert err.get("Message") == expected, f"expected message {expected!r}, got {err.get('Message')!r}"

    good_url = f"s3://{ctx.unique_name('sim2real-import-ctrl-')}/data.csv"

    def _create_good():
        return sesv2.create_import_job(
            ImportDataSource={"DataFormat": "CSV", "S3Url": good_url},
            ImportDestination={"SuppressionListDestination": {"SuppressionListImportAction": "DELETE"}},
        )

    try:
        resp = _create_good()
    except ClientError as err:
        ctrl = err.response.get("Error", {})
        assert ctrl.get("Code") == "BadRequestException", (
            f"well-formed CreateImportJob unexpectedly failed: {ctrl!r}"
        )
        assert ctrl.get("Message") == SANDBOX_MESSAGE, (
            f"expected the SES sandbox refusal message, got {ctrl.get('Message')!r}"
        )
        # ImportJob is gated account-wide in the SES sandbox, so the well-formed control cannot run.
        return

    job_id = resp["JobId"]
    assert job_id, f"well-formed CreateImportJob succeeded but returned no JobId: {resp!r}"

    # Read back via GetImportJob so the stored job is checked, not the create response echo.
    got = sesv2.get_import_job(JobId=job_id)
    assert got["JobId"] == job_id, f"GetImportJob returned JobId {got.get('JobId')!r}, expected {job_id!r}"
    assert got["ImportDataSource"]["S3Url"] == good_url, (
        f"GetImportJob S3Url mismatch: expected {good_url!r}, got {got.get('ImportDataSource', {}).get('S3Url')!r}"
    )


def _error(fn):
    """Call fn() and return its botocore Error dict; raise if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
