"""get-insight-impact-graph-unknown-id-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-insight-impact-graph-unknown-id-fails"
GROUP = 'overly-permissive'
SERVICES = ['xray']


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError("expected the call to be rejected, it succeeded")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetInsightImpactGraph rejects a pattern-invalid InsightId with ValidationException and a
    well-formed never-issued one with InvalidRequestException "Insight not found", after
    GetInsightSummaries on an insights-enabled group succeeds as a control."""
    xr = ctx.client("xray")

    group_name = ctx.unique_name("sim2real-behav-xray-insight-grp-")[:32].rstrip("-")
    xr.create_group(
        GroupName=group_name,
        FilterExpression=f'service("{group_name}")',
        InsightsConfiguration={"InsightsEnabled": True, "NotificationsEnabled": False},
    )
    ctx.on_cleanup(lambda: xr.delete_group(GroupName=group_name))

    end = time.time()
    start = end - 3600
    summaries = xr.get_insight_summaries(
        StartTime=start, EndTime=end, GroupName=group_name, States=["ACTIVE"]
    )
    assert "InsightSummaries" in summaries, f"missing key: {list(summaries)}"
    assert isinstance(summaries["InsightSummaries"], list)

    malformed_code, malformed_message = _error(
        lambda: xr.get_insight_impact_graph(
            InsightId="11111111-2222-3333-4444-555555555555",
            StartTime=start,
            EndTime=end,
        )
    )
    assert malformed_code == "ValidationException", (
        f"expected ValidationException for a pattern-invalid InsightId, got {malformed_code}"
    )
    assert malformed_message == (
        "1 validation error detected: Value '11111111-2222-3333-4444-555555555555' at 'insightId' "
        "failed to satisfy constraint: Member must satisfy regular expression pattern: "
        "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}"
    ), f"unexpected message: {malformed_message!r}"

    well_formed_code, well_formed_message = _error(
        lambda: xr.get_insight_impact_graph(
            InsightId="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            StartTime=start,
            EndTime=end,
        )
    )
    assert well_formed_code == "InvalidRequestException", (
        f"expected InvalidRequestException for a well-formed but never-issued InsightId, "
        f"got {well_formed_code}"
    )
    assert well_formed_message == "Insight not found", (
        f"unexpected message: {well_formed_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
