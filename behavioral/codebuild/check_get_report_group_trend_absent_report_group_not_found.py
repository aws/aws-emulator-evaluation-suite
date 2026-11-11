"""get-report-group-trend-absent-report-group-not-found."""
from __future__ import annotations

CHECK = "get-report-group-trend-absent-report-group-not-found"
GROUP = "error-semantics"
SERVICES = ["codebuild"]

from behavioral_harness import tags


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetReportGroupTrend on a report group ARN never created raises ResourceNotFoundException naming the
    ARN, while on a real report group with no reports it returns empty rawData and a stats object."""
    codebuild = ctx.client("codebuild")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    missing_arn = (
        f"arn:aws:codebuild:{ctx.region}:{account_id}:report-group/"
        f"{ctx.unique_name('sim2real-nonexistent-rg-')}"
    )

    code, message = _client_error(
        lambda: codebuild.get_report_group_trend(reportGroupArn=missing_arn, trendField="PASS_RATE")
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == f"The provided report group {missing_arn} does not exist", message

    real_arn = _create_report_group(ctx)
    resp = codebuild.get_report_group_trend(reportGroupArn=real_arn, trendField="PASS_RATE")
    assert resp["rawData"] == [], f"expected no trend data for a fresh report group, got {resp['rawData']}"
    assert "stats" in resp, f"expected a stats key in the trend response, got keys {list(resp.keys())}"


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, so a target accepting what AWS refuses is not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_report_group(ctx) -> str:
    codebuild = ctx.client("codebuild")
    name = ctx.unique_name("sim2real-behav-rg-")
    resp = codebuild.create_report_group(
        name=name,
        type="TEST",
        exportConfig={"exportConfigType": "NO_EXPORT"},
        tags=[{"key": "sim2real", "value": "true"}],
    )
    arn = resp["reportGroup"]["arn"]
    ctx.on_cleanup(lambda: codebuild.delete_report_group(arn=arn, deleteReports=True))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
