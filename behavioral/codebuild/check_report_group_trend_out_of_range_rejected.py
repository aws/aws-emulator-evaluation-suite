"""report-group-trend-out-of-range-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "report-group-trend-out-of-range-rejected"
GROUP = "data-plane"
SERVICES = ["codebuild"]


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raised. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetReportGroupTrend refuses numOfReports 101 (model maximum 100) with an InvalidInputException
    validation message, while an in-range request on the same report group returns empty rawData."""
    codebuild = ctx.client("codebuild")
    name = ctx.unique_name("sim2real-behav-rg-")
    report_group_arn = codebuild.create_report_group(
        name=name, type="TEST", exportConfig={"exportConfigType": "NO_EXPORT"}
    )["reportGroup"]["arn"]
    ctx.on_cleanup(lambda: codebuild.delete_report_group(arn=report_group_arn, deleteReports=True))

    code, code_msg = _client_error(
        lambda: codebuild.get_report_group_trend(
            reportGroupArn=report_group_arn, trendField="PASS_RATE", numOfReports=101
        )
    )
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code!r}"
    assert code_msg == "1 validation error detected: Value '101' at 'numOfReports' failed to satisfy constraint: Member must have value less than or equal to 100", f"unexpected message: {code_msg!r}"

    # Positive control: an in-range request against the same (empty) report group succeeds.
    trend = codebuild.get_report_group_trend(
        reportGroupArn=report_group_arn, trendField="PASS_RATE", numOfReports=100
    )
    assert trend["rawData"] == [], f"expected empty rawData, got {trend['rawData']}"
    assert "stats" in trend, "response missing stats key"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
