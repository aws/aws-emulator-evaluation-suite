"""put-rum-events-unknown-app-monitor-rejected."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-rum-events-unknown-app-monitor-rejected"
GROUP = "error-semantics"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutRumEvents against a nonexistent AppMonitorId is rejected with AccessDeniedException and the
    exact permissions message, the fake id never appears in ListAppMonitors, and the same call against
    an existing app monitor's Id succeeds."""
    rum = ctx.client("rum")

    # Positive control: a real app monitor's Id accepts PutRumEvents.
    name = ctx.unique_name("sim2real-rum-putevt-")
    created = rum.create_app_monitor(Name=name, Domain="localhost", Tags={"Team": "rum-fidelity"})
    ctx.on_cleanup(lambda: rum.delete_app_monitor(Name=name))
    real_id = created["Id"]

    rum.put_rum_events(**_rum_events_payload(real_id))  # must not raise

    # Negative: a syntactically valid but never-issued AppMonitorId.
    fake_id = str(uuid.uuid4())
    while fake_id == real_id:
        fake_id = str(uuid.uuid4())

    code, message = _client_error(lambda: rum.put_rum_events(**_rum_events_payload(fake_id)))
    assert code == "AccessDeniedException", repr(code)
    assert message == "Caller principal does not have permissions for that resource.", message

    # Effect absence: no listed app monitor carries the fake ID.
    summaries = rum.list_app_monitors().get("AppMonitorSummaries", [])
    assert not any(s.get("Id") == fake_id for s in summaries), (
        f"fake app monitor id {fake_id!r} unexpectedly appeared in list_app_monitors"
    )


def _rum_events_payload(app_monitor_id: str) -> dict:
    return {
        "Id": app_monitor_id,
        "BatchId": str(uuid.uuid4()),
        "AppMonitorDetails": {},
        "UserDetails": {"sessionId": str(uuid.uuid4()), "userId": str(uuid.uuid4())},
        "RumEvents": [
            {
                "id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc),
                "type": "com.amazon.rum.session_start_event",
                "metadata": json.dumps({"version": "1.0.0", "domain": "localhost"}),
                "details": json.dumps({"version": "1.0.0"}),
            }
        ],
    }


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
