"""report-group-trend-empty-state-read."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "report-group-trend-empty-state-read"
GROUP = "data-plane"
SERVICES = ["codebuild"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetReportGroupTrend on a freshly created report group with zero reports
    returns an empty trend result set (no rawData points) rather than erroring."""
    codebuild = ctx.client("codebuild")

    name = ctx.unique_name("sim2real-behav-rg-")
    created = codebuild.create_report_group(
        name=name,
        type="TEST",
        exportConfig={"exportConfigType": "NO_EXPORT"},
    )
    arn = created["reportGroup"]["arn"]
    ctx.on_cleanup(lambda: codebuild.delete_report_group(arn=arn, deleteReports=True))

    resp = codebuild.get_report_group_trend(reportGroupArn=arn, trendField="PASS_RATE")

    assert "rawData" in resp, "response missing rawData key"
    assert resp["rawData"] == [], f"expected empty rawData for a report-less group, got {resp['rawData']}"
    stats = resp["stats"]
    assert stats == {"average": "", "max": "", "min": ""}, (
        "expected average/max/min as empty strings for a report-less group, "
        f"got {stats}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
