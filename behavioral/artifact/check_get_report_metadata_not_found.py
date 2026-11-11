"""get-report-metadata-not-found."""
from __future__ import annotations

import random
import string

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-report-metadata-not-found"
GROUP = "error-semantics"
SERVICES = ["artifact"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetReportMetadata on a well-formed unknown reportId fails UnauthorizedException, not
    ResourceNotFoundException, while a real reportId from ListReports succeeds."""
    art = ctx.client("artifact")
    fake_id = "report-" + "".join(random.choices(string.ascii_letters + string.digits, k=16))

    code, message = _error(lambda: art.get_report_metadata(reportId=fake_id))
    assert code == "UnauthorizedException", f"expected UnauthorizedException, got {code}"
    assert message == "Unauthorized", f"unexpected message {message!r}"

    # Positive control: a real, well-formed reportId still works.
    real = art.list_reports(maxResults=1)["reports"]
    assert len(real) == 1, "expected at least one report in the catalog for the control"
    ok = art.get_report_metadata(reportId=real[0]["id"])
    assert ok["reportDetails"]["id"] == real[0]["id"]


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
