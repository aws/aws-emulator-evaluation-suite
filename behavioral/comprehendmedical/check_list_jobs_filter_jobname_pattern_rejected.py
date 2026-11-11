"""list-jobs-filter-jobname-pattern-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-jobs-filter-jobname-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["comprehendmedical"]


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListPHIDetectionJobs rejects a Filter.JobName that violates the documented charset pattern."""
    cm = ctx.client("comprehendmedical")

    # JobName must match ^([\p{L}\p{Z}\p{N}_.:/=+\-%@]*)$ -- "#" and "!" are disallowed.
    code, message = _error(lambda: cm.list_phi_detection_jobs(Filter={"JobName": "bad#name#!"}))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    expected = r"1 validation error detected: Value at 'filter.jobName' failed to satisfy constraint: Member must satisfy regular expression pattern: ^([\p{L}\p{Z}\p{N}_.:/=+\-%@]*)$"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: a syntactically valid filter is accepted (even though it matches nothing).
    resp = cm.list_phi_detection_jobs(Filter={"JobName": "a-syntactically-valid-job-name"})
    assert "ComprehendMedicalAsyncJobPropertiesList" in resp


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
