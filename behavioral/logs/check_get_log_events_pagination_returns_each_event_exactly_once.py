"""get-log-events-pagination-returns-each-event-exactly-once."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-log-events-pagination-returns-each-event-exactly-once"
GROUP = 'log-events'
SERVICES = ['logs']

_TOTAL_EVENTS = 60
_WRITE_BATCH = 20
_PAGE_LIMIT = 7
#: 40 pages for 60 events at limit 7 is deliberately generous: GetLogEvents may return
#: FEWER events than the limit, and it may return an EMPTY page with a valid token, so
#: the ceiling must not be the thing that decides the verdict.
_PAGE_CEILING = 40


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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Paging forward through a stream with a small limit returns every event exactly once (no loss,
    no duplication), an empty page is not exhaustion, and the end of the stream is signalled by
    ``nextForwardToken`` repeating, which is asserted separately from the recovered set.
    """
    svc = ctx.client("logs")

    group = ctx.unique_name("sim2real-behav-lg-page-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    base = _now_ms() - _TOTAL_EVENTS * 10
    written = [f"sim2real-page-event-{i:03d}" for i in range(_TOTAL_EVENTS)]

    for start in range(0, _TOTAL_EVENTS, _WRITE_BATCH):
        chunk = written[start:start + _WRITE_BATCH]
        resp = svc.put_log_events(
            logGroupName=group,
            logStreamName=stream,
            logEvents=[
                {"timestamp": base + (start + i) * 10, "message": msg}
                for i, msg in enumerate(chunk)
            ],
        )
        assert "rejectedLogEventsInfo" not in resp, (
            f"a write batch was partially rejected, so fewer than {_TOTAL_EVENTS} events exist and "
            f"the pagination assertions below would be vacuous: {resp!r}"
        )

    # Separate ingestion latency from pagination: everything must be visible in one
    # unlimited read before paging begins.
    _poll_until(
        lambda: svc.get_log_events(
            logGroupName=group, logStreamName=stream, startFromHead=True
        ).get("events", []),
        lambda evs: len(evs) >= _TOTAL_EVENTS,
        timeout_s=150,
        interval_s=3.0,
        description=f"all {_TOTAL_EVENTS} written events become visible before paging starts",
    )

    accumulated: list[str] = []
    token: str | None = None
    pages_seen = 0
    token_repeated = False
    while pages_seen < _PAGE_CEILING:
        kwargs = {
            "logGroupName": group,
            "logStreamName": stream,
            "startFromHead": True,
            "limit": _PAGE_LIMIT,
        }
        if token is not None:
            kwargs["nextToken"] = token
        resp = svc.get_log_events(**kwargs)
        pages_seen += 1
        page = resp.get("events", [])
        assert len(page) <= _PAGE_LIMIT, (
            f"page {pages_seen} returned {len(page)!r} events for limit={_PAGE_LIMIT!r}; a limit "
            "that is exceeded means the caller cannot bound a page at all"
        )
        accumulated.extend(e["message"] for e in page)
        new_token = resp.get("nextForwardToken")
        # An empty page with a valid token is documented and is NOT exhaustion; only a
        # repeated forward token ends the stream.
        if new_token is not None and new_token == token:
            token_repeated = True
            break
        token = new_token

    assert accumulated == written, (
        f"paging returned {len(accumulated)!r} events for {len(written)!r} written; missing "
        f"{[m for m in written if m not in accumulated]!r} and unexpected "
        f"{[m for m in accumulated if m not in written]!r}"
    )
    assert len(accumulated) == len(set(accumulated)), (
        "pagination returned duplicates: "
        f"{sorted(m for m in set(accumulated) if accumulated.count(m) > 1)!r}"
    )
    assert pages_seen > 1, (
        f"the whole stream came back in {pages_seen!r} page(s), so limit={_PAGE_LIMIT!r} was "
        "ignored and this check proved nothing about pagination"
    )
    assert token_repeated, (
        f"nextForwardToken never repeated across {pages_seen!r} pages, so the documented "
        "end-of-stream signal was never emitted and the loop exited on its own ceiling instead"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
