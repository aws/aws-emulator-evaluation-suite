"""list-findings-reports-empty-for-new-group."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "list-findings-reports-empty-for-new-group"
GROUP = "data-plane"
SERVICES = ["codeguruprofiler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly created profiling group has never had a profile aggregated, so
    ListFindingsReports returns a successful, empty result rather than an error."""
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-behav-cgp-")
    cgp.create_profiling_group(
        profilingGroupName=name,
        agentOrchestrationConfig={"profilingEnabled": True},
        tags={"env": "sim2real-test"},
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=1)
    resp = cgp.list_findings_reports(profilingGroupName=name, startTime=start, endTime=end)
    assert resp["findingsReportSummaries"] == [], (
        f"expected no findings reports for a freshly created group, got "
        f"{resp['findingsReportSummaries']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
