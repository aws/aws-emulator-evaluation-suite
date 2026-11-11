"""test-metric-filter-matches-sample-events."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "test-metric-filter-matches-sample-events"
GROUP = "telemetry"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestMetricFilter returns the exact set of matched sample log lines for a
    pattern, without creating or persisting any log group, stream, or filter."""
    logs = ctx.client("logs")
    messages = [
        "2024-01-01T00:00:00Z INFO service started",
        "2024-01-01T00:00:01Z ERROR failed to connect to db",
        "2024-01-01T00:00:02Z INFO request handled",
        "2024-01-01T00:00:03Z ERROR timeout waiting for upstream",
        "2024-01-01T00:00:04Z WARN slow response",
    ]

    resp = logs.test_metric_filter(filterPattern="ERROR", logEventMessages=messages)
    matches = resp["matches"]

    matched_messages = {m["eventMessage"] for m in matches}
    expected = {messages[1], messages[3]}
    assert matched_messages == expected, f"expected matches {expected}, got {matched_messages}"
    assert len(matches) == 2, f"expected exactly 2 matches, got {len(matches)}"

    # A pattern that matches nothing must return an empty list, not an error or a
    # spurious match -- this is the complementary boundary of the same oracle.
    resp_none = logs.test_metric_filter(
        filterPattern="NOPE_NOT_PRESENT_ANYWHERE", logEventMessages=messages
    )
    assert resp_none["matches"] == [], f"expected no matches, got {resp_none['matches']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
