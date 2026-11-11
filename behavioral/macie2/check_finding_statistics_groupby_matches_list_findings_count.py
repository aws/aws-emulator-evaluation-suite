"""finding-statistics-groupby-matches-list-findings-count."""
from __future__ import annotations

import time
from collections import Counter

from behavioral_harness import tags

CHECK = "finding-statistics-groupby-matches-list-findings-count"
GROUP = "data-plane"
SERVICES = ["macie2"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:macie")
def run(ctx) -> None:
    """GetFindingStatistics(groupBy=type) counts sum to the same total as ListFindings for the same criteria."""
    _ensure_macie_enabled(ctx)
    macie = ctx.client("macie2")
    # Only the sample findings this run creates: createdAt is at or after the request.
    created_after_ms = int(time.time() * 1000) - 1000
    macie.create_sample_findings()

    criteria = {"criterion": {"sample": {"eq": ["true"]}, "createdAt": {"gte": created_after_ms}}}
    _poll_until(
        lambda: macie.list_findings(findingCriteria=criteria).get("findingIds", []),
        lambda ids: len(ids) > 0,
        timeout_s=90,
        interval_s=3,
    )

    # GetFindingStatistics and ListFindings/GetFindings are backed by separate indexes that
    # can momentarily disagree right after CreateSampleFindings. Take a coherent snapshot by
    # polling until three independent reads (stats total, id-list length, and per-type tally
    # from the fetched findings) all agree, rather than comparing two calls made moments apart.
    def _snapshot():
        finding_ids = macie.list_findings(findingCriteria=criteria).get("findingIds", [])
        stats = macie.get_finding_statistics(findingCriteria=criteria, groupBy="type")["countsByGroup"]
        stats_total = sum(int(g["count"]) for g in stats)
        stats_by_type = {g["groupKey"]: int(g["count"]) for g in stats}
        findings = macie.get_findings(findingIds=finding_ids)["findings"] if finding_ids else []
        tally = dict(Counter(f["type"] for f in findings))
        return finding_ids, stats_total, stats_by_type, tally

    def _consistent(snap):
        finding_ids, stats_total, stats_by_type, tally = snap
        return len(finding_ids) > 0 and stats_total == len(finding_ids) and stats_by_type == tally

    finding_ids, stats_total, stats_by_type, tally = _poll_until(
        _snapshot,
        _consistent,
        timeout_s=90,
        interval_s=3,
    )
    assert stats_total == len(finding_ids), (
        f"GetFindingStatistics total {stats_total} != ListFindings count {len(finding_ids)}"
    )
    assert stats_by_type == tally, (
        f"GetFindingStatistics per-type counts {stats_by_type} != GetFindings tally {tally}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _ensure_macie_enabled(ctx) -> None:
    """Enable Macie when the account has no session, and disable it again at cleanup so the
    account-wide setting ends in the state it started in."""
    from botocore.exceptions import ClientError

    macie = ctx.client("macie2")
    try:
        macie.get_macie_session()
        return
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code not in ("ResourceNotFoundException", "AccessDeniedException"):
            raise
    try:
        macie.enable_macie()
    except ClientError as exc2:
        if exc2.response["Error"]["Code"] != "ConflictException":
            raise
        return
    ctx.on_cleanup(macie.disable_macie)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
