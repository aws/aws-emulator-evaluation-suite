"""get-report-metadata-invalid-id-pattern-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-report-metadata-invalid-id-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["artifact"]


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetReportMetadata with a reportId outside ^report-[a-zA-Z0-9]{16}$ fails UnauthorizedException,
    not ValidationException, while a real reportId from ListReports succeeds."""
    art = ctx.client("artifact")

    bad_id = "not a valid report id!"
    code, message = _error(lambda: art.get_report_metadata(reportId=bad_id))
    assert code == "UnauthorizedException", f"expected UnauthorizedException, got {code}"
    assert message == "Unauthorized", f"expected AWS's exact refusal message, got {message!r}"

    # Positive control: a real, well-formed reportId still works.
    real = art.list_reports(maxResults=1)["reports"]
    assert len(real) == 1, "expected at least one report in the catalog for the control"
    ok = art.get_report_metadata(reportId=real[0]["id"])
    assert ok["reportDetails"]["id"] == real[0]["id"], (
        f"expected reportDetails.id {real[0]['id']!r}, got {ok['reportDetails'].get('id')!r}"
    )


def _error(fn):
    """Call fn() and return its ClientError (code, message); a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
