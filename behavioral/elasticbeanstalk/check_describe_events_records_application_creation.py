"""describe-events-records-application-creation."""
from __future__ import annotations

import datetime as _dt
import time

from behavioral_harness import tags

CHECK = "describe-events-records-application-creation"
GROUP = 'events'
SERVICES = ['elasticbeanstalk']

# com.amazonaws.elasticbeanstalk#EventSeverity, most to least severe.
_SEVERITIES = ["FATAL", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"]


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeEvents surfaces an event for a newly created application, scoped to that app."""
    eb = ctx.client("elasticbeanstalk")
    before = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(minutes=1)
    app_name = ctx.unique_name("sim2real-behav-eb-app-")
    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda _n=app_name: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True))

    def probe():
        return eb.describe_events(ApplicationName=app_name)["Events"]

    events = _poll_until(
        probe, lambda evs: len(evs) > 0, timeout_s=180, interval_s=10,
        description=f"an event recorded for application {app_name}",
    )
    after = _dt.datetime.now(_dt.timezone.utc)
    assert events, "application creation must produce at least one event"
    assert all(e["ApplicationName"] == app_name for e in events), (
        f"events filtered by ApplicationName must only contain that application's events, got "
        f"{[e.get('ApplicationName') for e in events]!r}"
    )
    assert any(
        "createApplication" in e["Message"] or "Created new Application" in e["Message"]
        for e in events
    ), f"expected a createApplication event among this application's events, got {[e['Message'] for e in events]!r}"
    severities = {e["Severity"] for e in events}
    assert severities <= set(_SEVERITIES), (
        f"every event Severity must come from the modeled EventSeverity enum {_SEVERITIES!r}, got "
        f"{severities!r}"
    )
    # EventDate is the server's clock; the window allows 2 minutes of skew against the runner's.
    assert all(before <= e["EventDate"] <= after for e in events) or all(
        before <= e["EventDate"] <= after + _dt.timedelta(minutes=2) for e in events
    ), (
        f"every event's EventDate must fall within [{before!r}, {after!r} + 2 min], got "
        f"{[e['EventDate'] for e in events]!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
