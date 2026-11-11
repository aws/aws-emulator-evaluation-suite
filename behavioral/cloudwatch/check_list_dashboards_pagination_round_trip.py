"""list-dashboards-pagination-round-trip."""
from __future__ import annotations

import concurrent.futures
import json
import random
import time

from behavioral_harness import tags

CHECK = "list-dashboards-pagination-round-trip"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]

# ListDashboards has no page-size parameter: it always returns up to 1000 entries per call
# (see API_ListDashboards.html), so forcing a second NextToken page requires creating 1001
# dashboards. The creates and deletes are batched/parallelised, and every dashboard is deleted
# in cleanup.
_DASHBOARD_COUNT = 1001


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDashboards' NextToken paginates through every created dashboard exactly once."""
    cw = ctx.client("cloudwatch")
    prefix = ctx.unique_name("sim2real-cwdb-")
    names = [f"{prefix}{i:04d}" for i in range(_DASHBOARD_COUNT)]
    body = json.dumps({"widgets": []})

    def _put(name: str) -> None:
        _retry_throttled(lambda: cw.put_dashboard(DashboardName=name, DashboardBody=body))

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(_put, names))

    def _cleanup() -> None:
        chunks = [names[i : i + 100] for i in range(0, len(names), 100)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(
                pool.map(
                    lambda chunk: _retry_throttled(
                        lambda: cw.delete_dashboards(DashboardNames=chunk)
                    ),
                    chunks,
                )
            )

    ctx.on_cleanup(_cleanup)

    seen: list[str] = []
    token = None
    pages = 0
    while True:
        kwargs = {"DashboardNamePrefix": prefix}
        if token:
            kwargs["NextToken"] = token
        resp = cw.list_dashboards(**kwargs)
        seen.extend(entry["DashboardName"] for entry in resp.get("DashboardEntries", []))
        token = resp.get("NextToken")
        pages += 1
        if not token or pages > 10:
            break

    assert pages >= 2, f"expected ListDashboards to paginate across at least 2 pages, got {pages}"
    assert len(seen) == len(set(seen)), "ListDashboards returned a duplicate dashboard name across pages"
    missing = set(names) - set(seen)
    extra = set(seen) - set(names)
    assert not missing and not extra, f"pagination mismatch: missing={len(missing)} extra={len(extra)}"


def _retry_throttled(fn, *, attempts: int = 8, base_delay_s: float = 0.2):
    """1001 concurrent Put/DeleteDashboards calls routinely hit CloudWatch's real per-account rate
    limit; that is genuine asynchrony, not a check defect, so absorb it with a bounded exponential
    backoff instead of letting a transient Throttling error fail the whole batch."""
    from botocore.exceptions import ClientError

    delay = base_delay_s
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") != "Throttling" or attempt == attempts - 1:
                raise
            time.sleep(delay + random.uniform(0, delay))
            delay *= 2


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
