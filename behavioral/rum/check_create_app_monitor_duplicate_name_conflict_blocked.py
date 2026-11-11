"""create-app-monitor-duplicate-name-conflict-blocked."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-app-monitor-duplicate-name-conflict-blocked"
GROUP = "overly-permissive"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAppMonitor with a Name already in use is refused with ConflictException and leaves the
    original's configuration unchanged; once the original is deleted the same call succeeds with its
    own configuration.
    """
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-rum-dupname-")

    first = rum.create_app_monitor(Name=name, Domain="example.com")
    original_id = first["Id"]
    ctx.on_cleanup(lambda: _safe_delete(rum, name))

    code, message = _client_error(
        lambda: rum.create_app_monitor(Name=name, Domain="example.org")
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected_message = f"Resource {name} already exists"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the original app monitor's Id/Domain must be unchanged
    after = rum.get_app_monitor(Name=name)["AppMonitor"]
    assert after["Id"] == original_id, "duplicate create must not replace the Id"
    assert after["Domain"] == "example.com", "duplicate create must not overwrite Domain"

    # restore: freeing the Name (by deleting the original) makes the identical
    # call succeed -- the conflict tracks the live resource, not the string
    rum.delete_app_monitor(Name=name)
    _wait_deleted(rum, name)
    restored = rum.create_app_monitor(Name=name, Domain="example.org")
    assert restored["Id"] != original_id, "restored create under the freed Name must mint a new Id"
    restored_after = rum.get_app_monitor(Name=name)["AppMonitor"]
    assert restored_after["Domain"] == "example.org", "the identical call must now succeed with its own config"

    # positive control: creating a monitor under a genuinely distinct name succeeds
    other_name = ctx.unique_name("sim2real-rum-distinct-")
    rum.create_app_monitor(Name=other_name, Domain="example.net")
    ctx.on_cleanup(lambda: _safe_delete(rum, other_name))
    other = rum.get_app_monitor(Name=other_name)["AppMonitor"]
    assert other["Name"] == other_name, "distinct-name create must be retrievable under its own Name"


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn and return the (code, message) of the ClientError it raises; a success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _safe_delete(rum, name: str) -> None:
    try:
        rum.delete_app_monitor(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_deleted(rum, name: str, timeout_s: float = 60.0) -> None:
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
