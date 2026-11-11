"""update-app-monitor-on-deleted-resource-blocked."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-app-monitor-on-deleted-resource-blocked"
GROUP = "state-machine"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAppMonitor on an app monitor whose DeleteAppMonitor has completed is rejected with
    ResourceNotFoundException and its exact message, while UpdateAppMonitor on a live app monitor turns
    CwLogEnabled from False to True."""
    rum = ctx.client("rum")

    victim_name = ctx.unique_name("sim2real-rum-delupd-")
    rum.create_app_monitor(Name=victim_name, Domain="example.com", Tags={"sim2real:managed": "true"})
    rum.delete_app_monitor(Name=victim_name)
    _wait_deleted(ctx, rum, victim_name)

    err = _client_error(lambda: rum.update_app_monitor(Name=victim_name, CwLogEnabled=True))
    assert err["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err!r}"
    expected_message = f"Resource not found {victim_name}"
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # positive control: UpdateAppMonitor on a live app monitor succeeds and persists
    live_name = ctx.unique_name("sim2real-rum-liveupd-")
    rum.create_app_monitor(Name=live_name, Domain="example.com", Tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: rum.delete_app_monitor(Name=live_name))

    before = rum.get_app_monitor(Name=live_name)["AppMonitor"]
    before_cw_log_enabled = before.get("DataStorage", {}).get("CwLog", {}).get("CwLogEnabled", False)
    assert before_cw_log_enabled is False, f"expected CwLogEnabled False before update, got {before_cw_log_enabled!r}"

    rum.update_app_monitor(Name=live_name, CwLogEnabled=True)
    after = rum.get_app_monitor(Name=live_name)["AppMonitor"]
    after_cw_log_enabled = after["DataStorage"]["CwLog"]["CwLogEnabled"]
    assert after_cw_log_enabled is True, f"expected CwLogEnabled True after update, got {after_cw_log_enabled!r}"


def _client_error(fn: Callable[[], Any]) -> dict:
    """Call fn(); return the botocore Error dict (Code, Message). An unexpected SUCCESS raises,
    because an over-permissive target accepting the call is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _wait_deleted(ctx, rum, name: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rum.get_app_monitor(Name=name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2.0)
    raise AssertionError(f"app monitor {name!r} was never fully deleted within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
