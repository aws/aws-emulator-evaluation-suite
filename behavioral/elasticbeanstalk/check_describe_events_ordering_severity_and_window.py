"""describe-events-ordering-severity-and-window."""
from __future__ import annotations

import datetime as _dt
import time

from behavioral_harness import tags

CHECK = "describe-events-ordering-severity-and-window"
GROUP = 'events'
SERVICES = ['elasticbeanstalk']

# com.amazonaws.elasticbeanstalk#EventSeverity, most to least severe.
_SEVERITIES = ["FATAL", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"]


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition", ctx=None):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeEvents is returned most-recent-first, Severity acts as a minimum filter, the
    StartTime/EndTime window is honoured, and MaxRecords/NextToken paginate down the sequence.

    Reference: https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_DescribeEvents.html
    """
    eb = ctx.client("elasticbeanstalk")
    before = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(minutes=5)

    app_name = ctx.unique_name("sim2real-behav-eb-app-")
    tag = [{"Key": "sim2real", "Value": "true"}]
    eb.create_application(
        ApplicationName=app_name, Description="events ordering probe", Tags=tag
    )
    ctx.on_cleanup(
        lambda _n=app_name: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True)
    )

    # Each mutation waits for the preceding one's event and then past a one-second tick, so
    # events carry distinct timestamps even at second resolution.
    mutation_timeout_s = 60
    tick_s = 1.1

    def _events():
        return eb.describe_events(ApplicationName=app_name)["Events"]

    _poll_until(
        _events,
        lambda evs: len(evs) >= 1,
        timeout_s=_budget_s(ctx, mutation_timeout_s),
        interval_s=1,
        ctx=ctx,
        description=f"application creation event recorded for {app_name}",
    )
    time.sleep(tick_s)
    eb.update_application(ApplicationName=app_name, Description="events ordering probe v2")
    _poll_until(
        _events,
        lambda evs: len(evs) >= 2,
        timeout_s=_budget_s(ctx, mutation_timeout_s),
        interval_s=1,
        ctx=ctx,
        description=f"application update event recorded for {app_name}",
    )
    time.sleep(tick_s)
    eb.create_application_version(
        ApplicationName=app_name, VersionLabel=ctx.unique_name("sim2real-behav-v-"), Tags=tag
    )

    timeout_s = 180
    events = _poll_until(
        lambda: eb.describe_events(ApplicationName=app_name)["Events"],
        lambda evs: len(evs) >= 3,
        timeout_s=_budget_s(ctx, timeout_s),
        interval_s=1,
        ctx=ctx,
        description=f"at least three events recorded for application {app_name}",
    )
    assert all(e["ApplicationName"] == app_name for e in events), (
        f"events filtered by ApplicationName must contain only that application's events, got "
        f"{[e.get('ApplicationName') for e in events]!r}"
    )

    dates = [e["EventDate"] for e in events]
    assert all(dates[i] >= dates[i + 1] for i in range(len(dates) - 1)), (
        f"DescribeEvents is documented most-recent-first; the EventDate sequence must be "
        f"monotonically non-increasing, got {dates!r}. Asserting a SET here would let an emulator "
        f"return insertion order and pass."
    )
    assert len(set(dates)) > 1, (
        f"the probe deliberately spaced its mutations, so the events must carry distinct timestamps; "
        f"all {len(dates)} events report {dates[0]!r} — ordering cannot be evaluated"
    )
    severities = {e["Severity"] for e in events}
    assert severities <= set(_SEVERITIES), (
        f"every event Severity must come from the modeled EventSeverity enum {_SEVERITIES!r}, got "
        f"{severities!r}"
    )
    assert "INFO" in severities, (
        f"application creation and version creation emit INFO events, got {severities!r}"
    )

    warn_and_above = eb.describe_events(ApplicationName=app_name, Severity="WARN")["Events"]
    assert all(e["Severity"] in ("WARN", "ERROR", "FATAL") for e in warn_and_above), (
        f"Severity=WARN must return only WARN and above; got "
        f"{[e['Severity'] for e in warn_and_above]!r} — an emulator that ignores the Severity "
        f"parameter has been caught returning too much"
    )
    info_labels = {(e["EventDate"], e["Message"]) for e in events if e["Severity"] == "INFO"}
    returned = {(e["EventDate"], e["Message"]) for e in warn_and_above}
    assert not (info_labels & returned), (
        f"Severity=WARN must exclude the INFO events entirely; {len(info_labels & returned)} of them "
        f"came back"
    )
    all_severities = eb.describe_events(ApplicationName=app_name, Severity="TRACE")["Events"]
    assert len(all_severities) >= len(events), (
        f"Severity=TRACE is the least-severe minimum and must return at least as many events as an "
        f"unfiltered call, got {len(all_severities)} vs {len(events)}"
    )

    spanning = eb.describe_events(
        ApplicationName=app_name,
        StartTime=before,
        EndTime=_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(minutes=5),
    )["Events"]
    assert len(spanning) >= 3, (
        f"a window spanning the application's creation must return its events, got {len(spanning)} — "
        f"if this is 0 the window filter is dropping everything and the negative half below is "
        f"passing by construction"
    )
    closed_before = eb.describe_events(
        ApplicationName=app_name, StartTime=before - _dt.timedelta(days=2), EndTime=before
    )["Events"]
    assert closed_before == [], (
        f"a window that closes before the application existed must return no events, got "
        f"{len(closed_before)}: {closed_before!r}"
    )

    # CreateApplicationVersion keeps appending events for tens of seconds, so the head moves;
    # retry until a MaxRecords=1 page and a fresh full listing agree on it.
    for _attempt in range(6):
        page = eb.describe_events(ApplicationName=app_name, MaxRecords=1)
        fresh = eb.describe_events(ApplicationName=app_name)["Events"]
        assert len(page["Events"]) == 1, (
            f"MaxRecords=1 must return exactly one event, got {len(page['Events'])}"
        )
        if page["Events"][0]["EventDate"] == fresh[0]["EventDate"]:
            break
        time.sleep(2)
    else:
        raise AssertionError(
            f"the first page of a most-recent-first listing must start at the newest event "
            f"{fresh[0]['EventDate']!r}, got {page['Events'][0]['EventDate']!r} — the head of the "
            f"listing never stabilised across 6 attempts"
        )
    head = page["Events"][0]["EventDate"]
    assert page["Events"][0]["Message"] == fresh[0]["Message"], (
        f"the MaxRecords=1 page and the unfiltered listing must agree on the newest event, got "
        f"{page['Events'][0]['Message']!r} vs {fresh[0]['Message']!r}"
    )
    assert page.get("NextToken"), (
        f"with {len(fresh)} events and MaxRecords=1 the response must offer a NextToken, got "
        f"{page.get('NextToken')!r}"
    )
    second_page = eb.describe_events(
        ApplicationName=app_name, MaxRecords=1, NextToken=page["NextToken"]
    )["Events"]
    assert len(second_page) == 1, second_page
    assert second_page[0]["EventDate"] <= head, (
        f"the second page must continue the descending sequence, got "
        f"{second_page[0]['EventDate']!r} after {head!r}"
    )
    assert second_page[0]["Message"] != page["Events"][0]["Message"] or (
        second_page[0]["EventDate"] != page["Events"][0]["EventDate"]
    ), "paginating with NextToken must advance, not re-serve the first event"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
