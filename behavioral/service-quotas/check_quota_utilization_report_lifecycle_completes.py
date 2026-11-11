"""quota-utilization-report-lifecycle-completes."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "quota-utilization-report-lifecycle-completes"
GROUP = "state"
SERVICES = ["service-quotas"]

_TERMINAL = {"COMPLETED", "FAILED"}


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A quota utilization report reaches COMPLETED with its ReportId, a GeneratedAt and a TotalCount of
    at least the listed quotas, and repeated reads keep the same status, TotalCount and GeneratedAt."""
    sq = ctx.client("service-quotas")

    started = sq.start_quota_utilization_report()
    report_id = started["ReportId"]
    assert report_id, f"StartQuotaUtilizationReport returned an empty ReportId: {started!r}"

    def probe():
        return sq.get_quota_utilization_report(ReportId=report_id)

    final = _poll_until(probe, lambda r: r["Status"] in _TERMINAL, timeout_s=120.0, interval_s=5.0)

    assert final["Status"] == "COMPLETED", f"report ended in {final['Status']}: {final}"
    assert final["ReportId"] == report_id, f"expected ReportId {report_id!r}, got {final['ReportId']!r}"
    assert final["GeneratedAt"] is not None, f"COMPLETED report has no GeneratedAt: {final!r}"
    quotas = final["Quotas"]
    assert final["TotalCount"] >= len(quotas), (
        f"TotalCount {final['TotalCount']} understates {len(quotas)} returned Quotas records"
    )

    for _ in range(3):
        reread = probe()
        assert reread["Status"] == "COMPLETED", (
            f"a completed report regressed to {reread['Status']!r} on a read-only re-poll"
        )
        assert reread["TotalCount"] == final["TotalCount"], (
            f"TotalCount drifted on a read-only re-poll: {final['TotalCount']} -> {reread['TotalCount']}"
        )
        assert reread["GeneratedAt"] == final["GeneratedAt"], (
            f"GeneratedAt drifted on a read-only re-poll: {final['GeneratedAt']!r} -> {reread['GeneratedAt']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
