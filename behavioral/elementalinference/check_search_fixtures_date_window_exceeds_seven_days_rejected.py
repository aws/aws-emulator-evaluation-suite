"""search-fixtures-date-window-exceeds-seven-days-rejected."""
from __future__ import annotations

import datetime as dt

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "search-fixtures-date-window-exceeds-seven-days-rejected"
GROUP = "overly-permissive"
SERVICES = ["elementalinference"]


def _error_code(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SearchFixtures rejects a startDate..endDate window wider than 7 days with ValidationException."""
    ei = ctx.client("elementalinference")
    today = dt.date.today()
    start = (today - dt.timedelta(days=10)).isoformat()
    end = today.isoformat()  # 11-day window, exceeds the documented 7-day maximum

    code, message = _error_code(
        lambda: ei.search_fixtures(sport="basketball", startDate=start, endDate=end)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == (
        "The search window must not span more than 7 days. Narrow the range between startDate and endDate."
    ), message

    # Positive control: a same-day (0-day) window is accepted and returns a well-formed response.
    ok = ei.search_fixtures(sport="basketball", startDate=end, endDate=end)
    assert isinstance(ok["fixtures"], list), f"expected a fixtures list, got {ok.get('fixtures')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
