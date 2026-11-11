"""get-app-monitor-deleted-or-unknown-name-not-found."""
from __future__ import annotations

import json

import time
import uuid
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-app-monitor-deleted-or-unknown-name-not-found"
GROUP = "error-semantics"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutRumEvents to a live app monitor succeeds, and after DeleteAppMonitor, GetAppMonitor for
    its name and for a name never created both answer ResourceNotFoundException.
    """
    rum = ctx.client("rum")
    tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-rum"}

    control_name = ctx.unique_name("sim2real-rum-control-")
    control = rum.create_app_monitor(Name=control_name, Domain="example.com", Tags=tags)
    control_id = control["Id"]
    ctx.on_cleanup(lambda: rum.delete_app_monitor(Name=control_name))

    # positive control: a live app monitor accepts events without raising
    rum.put_rum_events(**_rum_event_payload(control_id))

    victim_name = ctx.unique_name("sim2real-rum-victim-")
    rum.create_app_monitor(Name=victim_name, Domain="example.com", Tags=tags)

    # positive control on the exact call under test: GetAppMonitor succeeds for a
    # live resource, so the ResourceNotFoundException below proves a real state
    # transition rather than a target that returns not-found unconditionally.
    live = rum.get_app_monitor(Name=victim_name)["AppMonitor"]
    assert live["Name"] == victim_name, f"expected {victim_name!r}, got {live['Name']!r}"

    # break exactly one thing: delete the victim app monitor (exercises DeleteAppMonitor)
    rum.delete_app_monitor(Name=victim_name)
    _wait_deleted(rum, victim_name)

    # the control-plane read path deterministically rejects the deleted name
    code, message = _client_error(lambda: rum.get_app_monitor(Name=victim_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == f"Resource not found {victim_name}", message

    # ...and a name that was never created at all fails exactly the same way
    never_created_name = ctx.unique_name("sim2real-rum-ghost-")
    code, message = _client_error(lambda: rum.get_app_monitor(Name=never_created_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == f"Resource not found {never_created_name}", message


def _client_error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _rum_event_payload(app_monitor_id: str) -> dict[str, Any]:
    event_id = str(uuid.uuid4())
    return {
        "Id": app_monitor_id,
        "BatchId": str(uuid.uuid4()),
        "AppMonitorDetails": {"id": app_monitor_id, "version": "1.0"},
        "UserDetails": {"sessionId": str(uuid.uuid4()), "userId": str(uuid.uuid4())},
        "RumEvents": [
            {
                "id": event_id,
                "timestamp": int(time.time()),
                "type": "com.amazon.rum.page_view_event",
                "details": '{"pageId": "/sim2real"}',
                "metadata": json.dumps({"version": "1.0.0", "domain": "example.com", "pageId": "/sim2real"}),
            }
        ],
    }


def _wait_deleted(rum, name: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            code, _ = _client_error(lambda: rum.get_app_monitor(Name=name))
        except AssertionError:
            code = None
        if code == "ResourceNotFoundException":
            return
        time.sleep(2.0)
    raise AssertionError(f"app monitor {name!r} was never fully deleted within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


