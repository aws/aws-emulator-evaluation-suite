"""filter-log-events-unstructured-pattern-grammar."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "filter-log-events-unstructured-pattern-grammar"
GROUP = 'log-events'
SERVICES = ['logs']


# ===== helpers =====
def _now_ms() -> int:
    return int(time.time() * 1000)


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


# ===== end helpers =====


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """FilterLogEvents implements the unstructured filter-pattern grammar: case-sensitive terms,
    implicit AND, quoted exact phrases, ``-`` exclusion and ``?`` OR, each case built so that a
    matcher treating the whole pattern as one substring returns the wrong set.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-textfilter-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    # marker -> message. Markers are unique lowercase tokens that appear in no
    # filter pattern below, so they never perturb a match.
    events = {
        "mk-a": "ERROR connection refused by upstream mk-a",
        "mk-b": "ERROR request timeout after 30s mk-b",
        "mk-c": "WARN disk usage 91 percent mk-c",
        "mk-d": "INFO connection established mk-d",
        "mk-e": "error lowercase must be excluded mk-e",
        "mk-f": "refused connection words swapped mk-f",
    }
    base = _now_ms()
    ordered = sorted(events.items())
    svc.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[
            {"timestamp": base + i * 10, "message": msg} for i, (_m, msg) in enumerate(ordered)
        ],
    )

    def _all_markers():
        found = set()
        for ev in svc.filter_log_events(logGroupName=group).get("events", []):
            for marker in events:
                if marker in ev["message"]:
                    found.add(marker)
        return found

    _poll_until(
        _all_markers,
        lambda found: found == set(events),
        timeout_s=60,
        interval_s=2.0,
        description="all 6 seeded events become filterable",
    )

    def _markers_for(pattern):
        resp = svc.filter_log_events(logGroupName=group, filterPattern=pattern)
        found = set()
        for ev in resp.get("events", []):
            hits = [m for m in events if m in ev["message"]]
            assert hits, f"FilterLogEvents({pattern!r}) returned an event we never wrote: {ev!r}"
            found.update(hits)
        return found

    cases = [
        (
            "ERROR",
            {"mk-a", "mk-b"},
            "terms are CASE SENSITIVE: 'error' (mk-e) must not match",
        ),
        (
            "ERROR timeout",
            {"mk-b"},
            "space-separated terms are an implicit AND, not an OR",
        ),
        (
            '"connection refused"',
            {"mk-a"},
            "a quoted phrase must match adjacent, in-order words only (mk-f excluded)",
        ),
        (
            "ERROR -timeout",
            {"mk-a"},
            "'-' excludes: ERROR AND NOT timeout",
        ),
        (
            "?ERROR ?WARN",
            {"mk-a", "mk-b", "mk-c"},
            "'?' makes terms optional, i.e. a union",
        ),
    ]

    failures = {}
    for pattern, expected, why in cases:
        got = _markers_for(pattern)
        if got != expected:
            failures[pattern] = f"expected {sorted(expected)}, got {sorted(got)} ({why})"

    assert not failures, (
        f"FilterLogEvents unstructured filter-pattern grammar mismatches: {failures!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
