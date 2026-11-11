"""list-report-groups-reflects-created."""
from __future__ import annotations

import time

from behavioral_harness import tags

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")

def _create_report_group(cb, ctx, tags=None):
    """Create a uniquely-named TEST report group; register teardown; return its reportGroup dict."""
    kwargs = {"name": ctx.unique_name("sim2real-behav-rg-"), "type": "TEST",
              "exportConfig": {"exportConfigType": "NO_EXPORT"}}
    if tags is not None:
        kwargs["tags"] = tags
    rg = cb.create_report_group(**kwargs)["reportGroup"]
    ctx.on_cleanup(lambda: cb.delete_report_group(arn=rg["arn"], deleteReports=True))
    return rg

CHECK = "list-report-groups-reflects-created"
GROUP = 'lifecycle'
SERVICES = ['codebuild']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListReportGroups includes a just-created report group's ARN (membership of
    our own uniquely-named resource — never an unscoped count)."""
    cb = ctx.client("codebuild")
    rg = _create_report_group(cb, ctx, tags=[{"key": "sim2real", "value": "1"}])
    arn = rg["arn"]

    def _arns():
        arns = set()
        paginator = cb.get_paginator("list_report_groups")
        for page in paginator.paginate():
            for a in page.get("reportGroups", []):
                arns.add(a)
        return arns

    found = _poll_until(_arns, lambda a: arn in a, timeout_s=30, interval_s=2)
    assert arn in found, f"expected {arn!r} in ListReportGroups, got {sorted(found)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
