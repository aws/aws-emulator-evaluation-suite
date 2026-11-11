"""list-account-activities-concurrent-reads-consistent."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "list-account-activities-concurrent-reads-consistent"
GROUP = "concurrency"
SERVICES = ["freetier"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent ListAccountActivities calls all return the same set of activity ids, empty or not."""
    freetier = ctx.client("freetier")

    def _call(_):
        resp = freetier.list_account_activities(maxResults=50)
        return tuple(sorted(a["activityId"] for a in resp.get("activities", [])))

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_call, range(8)))

    assert len(set(results)) == 1, set(results)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
