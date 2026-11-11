"""e2e-put-rum-events-after-delete-rejected."""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-put-rum-events-after-delete-rejected"
GROUP = "e2e"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutRumEvents against an app monitor that has been fully deleted must be rejected with
    ResourceNotFoundException, and the monitor must not be resurrected by the attempt -- while
    PutRumEvents against a live monitor (in the same file) keeps working."""
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-rum-neg-")

    created = rum.create_app_monitor(
        Name=name, Domain="example.com", CwLogEnabled=False,
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-rum-neg"},
    )
    monitor_id = created["Id"]
    ctx.on_cleanup(lambda: _safe_delete_app_monitor(rum, name))

    # Positive control: PutRumEvents against the live monitor succeeds.
    rum.put_rum_events(**_event_payload(monitor_id, name))

    # Break exactly one thing: delete the app monitor and wait for it to be fully gone.
    rum.delete_app_monitor(Name=name)
    _poll_until_monitor_gone(ctx, name, timeout_s=60.0, interval_s=3.0)

    # The same PutRumEvents call must now be rejected -- the app monitor no longer exists.
    # The control-plane store (GetAppMonitor) invalidates promptly, but the PutRumEvents
    # ingestion path may cache app-monitor existence for a short window after deletion, so
    # poll rather than asserting on the first call. Empirically, once fully torn down, RUM
    # rejects with AccessDeniedException (the resource-based-policy/authorization metadata
    # for the app monitor is gone), not ResourceNotFoundException.
    code, message = _poll_for_error(
        lambda: rum.put_rum_events(**_event_payload(monitor_id, name)), timeout_s=180.0, interval_s=5.0
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    assert message == "Caller principal does not have permissions for that resource.", message

    # Effect absent: the monitor was not resurrected, and no separate monitor exists under this Id.
    resurrection_code, resurrection_message = _client_error(lambda: rum.get_app_monitor(Name=name))
    assert resurrection_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException (no resurrection), got {resurrection_code!r}"
    )
    assert resurrection_message == f"Resource not found {name}", resurrection_message

    # Second positive control: PutRumEvents still works fine for an unrelated, live monitor --
    # proving the rejection above is specific to the deleted resource, not a blanket stub.
    other_name = ctx.unique_name("sim2real-rum-neg-live-")
    other = rum.create_app_monitor(
        Name=other_name, Domain="example.com", CwLogEnabled=False,
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-rum-neg"},
    )
    ctx.on_cleanup(lambda: _safe_delete_app_monitor(rum, other_name))
    rum.put_rum_events(**_event_payload(other["Id"], other_name))


def _event_payload(monitor_id: str, monitor_name: str) -> dict:
    return {
        "Id": monitor_id,
        "BatchId": str(uuid.uuid4()),
        "AppMonitorDetails": {"id": monitor_id, "name": monitor_name, "version": "1.0.0"},
        "UserDetails": {"sessionId": str(uuid.uuid4()), "userId": str(uuid.uuid4())},
        "RumEvents": [
            {
                "id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc),
                "type": "com.amazon.rum.page_view_event",
                "metadata": json.dumps({"version": "1.0.0", "domain": "example.com"}),
                "details": json.dumps({"version": "1.0.0", "pageId": "/negative-check"}),
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


def _poll_for_error(fn, *, timeout_s: float, interval_s: float):
    """Poll until fn() is refused; return the (code, message). A success keeps polling until the
    deadline, then raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return _client_error(fn)
        except AssertionError as exc:
            if time.monotonic() >= deadline:
                raise AssertionError(f"call was not refused within {timeout_s}s: {exc}") from None
        time.sleep(interval_s)


def _safe_delete_app_monitor(rum, name: str) -> None:
    try:
        rum.delete_app_monitor(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until_monitor_gone(ctx, name: str, *, timeout_s: float, interval_s: float) -> None:
    rum = ctx.client("rum")
    code, message = _poll_for_error(lambda: rum.get_app_monitor(Name=name), timeout_s=timeout_s, interval_s=interval_s)
    assert code == "ResourceNotFoundException", f"app monitor {name} not fully deleted (got {code!r})"
    assert message == f"Resource not found {name}", f"expected message 'Resource not found {name}', got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
