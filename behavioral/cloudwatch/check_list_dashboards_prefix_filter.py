"""list-dashboards-prefix-filter."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "list-dashboards-prefix-filter"
GROUP = 'dashboards'
SERVICES = ['cloudwatch']

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDashboards with DashboardNamePrefix returns only matching dashboards."""
    cw = ctx.client("cloudwatch")
    prefix = ctx.unique_name("sim2real-behav-cwprobe-pfx-")
    name_a = f"{prefix}-alpha"
    name_b = f"{prefix}-beta"
    other = ctx.unique_name("sim2real-behav-cwprobe-other-")
    ctx.on_cleanup(lambda _n=name_a: cw.delete_dashboards(DashboardNames=[_n]))
    ctx.on_cleanup(lambda _n=name_b: cw.delete_dashboards(DashboardNames=[_n]))
    ctx.on_cleanup(lambda _n=other: cw.delete_dashboards(DashboardNames=[_n]))

    body = json.dumps({"widgets": []})
    cw.put_dashboard(DashboardName=name_a, DashboardBody=body)
    cw.put_dashboard(DashboardName=name_b, DashboardBody=body)
    cw.put_dashboard(DashboardName=other, DashboardBody=body)

    def probe():
        return cw.list_dashboards(DashboardNamePrefix=prefix)

    resp = _poll_until(probe, lambda r: len(r.get("DashboardEntries", [])) >= 2, timeout_s=20, interval_s=2)
    names = {e["DashboardName"] for e in resp["DashboardEntries"]}
    assert names == {name_a, name_b}, f"expected only prefix-matching dashboards, got {names}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
