"""batch-get-reports-invalid-arn."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-get-reports-invalid-arn"
GROUP = 'error-semantics'
SERVICES = ['codebuild']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchGetReports refuses a malformed report ARN with InvalidInputException "Invalid report ARN",
    while a well-formed ARN of a missing report is returned in reportsNotFound."""
    cb = ctx.client("codebuild")

    code, message = _error(lambda: cb.batch_get_reports(reportArns=["not-an-arn"]))
    assert (code, message) == ("InvalidInputException", "Invalid report ARN"), (code, message)

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    well_formed_missing = (
        f"arn:aws:codebuild:{ctx.region}:{account_id}:report/"
        f"{ctx.unique_name('sim2real-cb-rep-')}:{uuid.uuid4()}"
    )
    resp = cb.batch_get_reports(reportArns=[well_formed_missing])
    assert resp["reports"] == [], f"expected no reports, got {resp['reports']!r}"
    assert resp["reportsNotFound"] == [well_formed_missing], (
        f"expected reportsNotFound == [{well_formed_missing!r}], got "
        f"{resp['reportsNotFound']!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raised. An unexpected
    SUCCESS raises, so an over-permissive target is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
