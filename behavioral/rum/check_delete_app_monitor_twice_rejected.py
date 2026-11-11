"""delete-app-monitor-twice-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-app-monitor-twice-rejected"
GROUP = "overly-permissive"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second DeleteAppMonitor call on an app monitor that has already fully disappeared fails
    with ResourceNotFoundException rather than a false/idempotent success."""
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-behav-appmon-")
    rum.create_app_monitor(Name=name, Domain="example.com", Tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: _safe_delete_app_monitor(ctx, name))

    rum.delete_app_monitor(Name=name)

    # Wait for the delete to fully land (GetAppMonitor starts raising ResourceNotFoundException)
    # before probing the second delete, so we observe the terminal state rather than a
    # transient DELETING conflict.
    _wait_not_found(rum, name, timeout_s=60.0)

    code, message = _client_error(lambda: rum.delete_app_monitor(Name=name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = f"Resource not found {name}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _safe_delete_app_monitor(ctx, name: str) -> None:
    rum = ctx.client("rum")
    try:
        rum.delete_app_monitor(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _client_error(fn):
    """Call fn and return the (code, message) of the ClientError it raises; a success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _wait_not_found(rum, name: str, timeout_s: float = 60.0, interval_s: float = 2.0) -> None:
    """Poll GetAppMonitor until it raises ResourceNotFoundException; a timeout raises."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rum.get_app_monitor(Name=name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"app monitor {name!r} still readable after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
