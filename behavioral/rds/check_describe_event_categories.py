"""describe-event-categories."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-event-categories"
GROUP = 'events'
SERVICES = ['rds']


def _rejection(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeEventCategories is non-empty unfiltered and for SourceType 'db-instance', and an
    unrecognized SourceType is rejected with InvalidParameterValue rather than ignored."""
    rds = ctx.client("rds")
    resp = rds.describe_event_categories()
    unfiltered = resp.get("EventCategoriesMapList", [])
    assert unfiltered, "expected a non-empty event category catalog"

    resp2 = rds.describe_event_categories(SourceType="db-instance")
    filtered = resp2.get("EventCategoriesMapList", [])
    assert filtered, "expected non-empty categories for SourceType=db-instance"
    assert all(m["SourceType"] == "db-instance" for m in filtered), (
        f"expected every entry to report SourceType=db-instance, got {filtered}"
    )

    err = _rejection(lambda: rds.describe_event_categories(SourceType="not-a-real-source-type"))
    # message varies: it enumerates every valid source type, a list that grows as RDS adds
    # event sources, so the stable text before that list is asserted exactly.
    assert err.get("Code") == "InvalidParameterValue", f"expected InvalidParameterValue, got {err}"
    message = err.get("Message") or ""
    prefix = "Invalid event source type. Feature may be disabled. Valid types are "
    assert message.startswith(prefix), f"expected {prefix!r}..., got {message!r}"
    assert "'db-instance'" in message[len(prefix):], (
        f"expected the valid types to list 'db-instance', got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
