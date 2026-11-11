"""concurrent-differently-filtered-calls-do-not-cross-contaminate."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-differently-filtered-calls-do-not-cross-contaminate"
GROUP = "concurrency"
SERVICES = ["bcm-recommended-actions"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """16 concurrent ListRecommendedActions calls interleaving SEVERITY=CRITICAL and SEVERITY=INFO
    filters each return only actions of their own severity, and all calls with the same filter
    return the same id set: concurrent requests never cross-contaminate."""
    client = ctx.client("bcm-recommended-actions")

    filter_critical = {
        "actions": [{"key": "SEVERITY", "matchOption": "EQUALS", "values": ["CRITICAL"]}]
    }
    filter_info = {"actions": [{"key": "SEVERITY", "matchOption": "EQUALS", "values": ["INFO"]}]}

    def _call(i: int):
        tag, action_filter = ("critical", filter_critical) if i % 2 == 0 else ("info", filter_info)
        resp = client.list_recommended_actions(filter=action_filter)
        return tag, resp["recommendedActions"]

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_call, range(16)))

    assert len(results) == 16, f"expected 16 concurrent call results, got {len(results)}"
    for tag, actions in results:
        expected_severity = "CRITICAL" if tag == "critical" else "INFO"
        for action in actions:
            assert action["severity"] == expected_severity, (tag, action["severity"])

    critical_id_sets = {frozenset(a["id"] for a in actions) for tag, actions in results if tag == "critical"}
    info_id_sets = {frozenset(a["id"] for a in actions) for tag, actions in results if tag == "info"}
    assert len(critical_id_sets) == 1, "concurrent CRITICAL-filtered calls disagreed with each other"
    assert len(info_id_sets) == 1, "concurrent INFO-filtered calls disagreed with each other"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
