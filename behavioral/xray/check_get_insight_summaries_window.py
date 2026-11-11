"""get-insight-summaries-window."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-insight-summaries-window"
GROUP = 'trace-data-plane'
SERVICES = ['xray']


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetInsightSummaries is group-scoped: it requires GroupName/GroupARN, accepts a single State
    filter plus a time window, and returns an InsightSummaries list even when the group has no
    insights. Omitting the group is rejected, and supplying more than one State is rejected."""
    xr = ctx.client("xray")
    name = ctx.unique_name("sim2real-behav-xray-grp-")[:32].rstrip("-")
    xr.create_group(
        GroupName=name,
        FilterExpression='service("sim2real-behav")',
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: xr.delete_group(GroupName=name))

    end = time.time()
    start = end - 6 * 3600
    resp = xr.get_insight_summaries(GroupName=name, States=["ACTIVE"], StartTime=start, EndTime=end)
    assert "InsightSummaries" in resp, f"missing key: {list(resp)}"
    assert resp["InsightSummaries"] == [], (
        f"a group created seconds ago cannot yet have any insights: {resp['InsightSummaries']}"
    )

    code, message = _error(
        lambda: xr.get_insight_summaries(States=["ACTIVE"], StartTime=start, EndTime=end)
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == "Provide either GroupName or GroupARN", f"unexpected message: {message!r}"

    code2, message2 = _error(
        lambda: xr.get_insight_summaries(
            GroupName=name, States=["ACTIVE", "CLOSED"], StartTime=start, EndTime=end
        )
    )
    assert code2 == "ValidationException", f"expected ValidationException, got {code2}"
    assert message2 == (
        "1 validation error detected: Value '[ACTIVE, CLOSED]' at 'states' failed to satisfy "
        "constraint: Member must have length less than or equal to 1"
    ), f"unexpected message: {message2!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
