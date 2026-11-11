"""get-insight-events-unknown-id-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-insight-events-unknown-id-fails"
GROUP = 'overly-permissive'
SERVICES = ['xray']


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetInsightEvents for a well-formed but nonexistent InsightId fails with
    InvalidRequestException "Insight not found", after GetInsightSummaries succeeds as a control."""
    xr = ctx.client("xray")
    name = ctx.unique_name("sim2real-behav-xray-grp-")[:32].rstrip("-")
    xr.create_group(GroupName=name, FilterExpression='service("sim2real-behav")')
    ctx.on_cleanup(lambda: xr.delete_group(GroupName=name))

    end = time.time()
    resp = xr.get_insight_summaries(
        GroupName=name, States=["ACTIVE"], StartTime=end - 3600, EndTime=end
    )
    assert "InsightSummaries" in resp, f"missing key: {list(resp)}"

    code, message = _error(
        lambda: xr.get_insight_events(InsightId="12345678-1234-4123-8123-123456789012")
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == "Insight not found", f"unexpected message: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
