"""create-app-monitor-duplicate-name-conflict-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-app-monitor-duplicate-name-conflict-rejected"
GROUP = "error-semantics"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAppMonitor with a Name already in use is refused as a conflict and the original's
    configuration survives; after the original is deleted the identical create succeeds.
    """
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-rum-dupe-")
    resource_tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-rum-dupe"}

    # Positive control: the first create succeeds.
    rum.create_app_monitor(Name=name, Domain="original.example.com", Tags=resource_tags)
    ctx.on_cleanup(lambda: _safe_delete(rum, name))

    original = rum.get_app_monitor(Name=name)["AppMonitor"]
    assert original["Domain"] == "original.example.com", (
        f"expected the freshly created monitor to report its own Domain, got {original['Domain']!r}"
    )

    # Break exactly one thing: re-create under the same Name.
    code, message = _client_error(
        lambda: rum.create_app_monitor(Name=name, Domain="hijacked.example.com", Tags=resource_tags)
    )
    assert code == "ConflictException", f"expected ConflictException for a duplicate Name, got {code!r}"
    expected_message = f"Resource {name} already exists"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absence: the original app monitor was not overwritten.
    unchanged = rum.get_app_monitor(Name=name)["AppMonitor"]
    assert unchanged["Domain"] == "original.example.com", (
        f"a rejected duplicate create must not mutate Domain, got {unchanged['Domain']!r}"
    )
    assert unchanged["Id"] == original["Id"], (
        f"a rejected duplicate create must not replace Id: expected {original['Id']!r}, got {unchanged['Id']!r}"
    )

    # Restore: free the Name by deleting the original, then prove the
    # identical create succeeds.
    rum.delete_app_monitor(Name=name)
    _wait_not_found(rum, name)

    rum.create_app_monitor(Name=name, Domain="hijacked.example.com", Tags=resource_tags)
    reused = rum.get_app_monitor(Name=name)["AppMonitor"]
    assert reused["Domain"] == "hijacked.example.com", (
        f"expected the freed Name to accept the previously-rejected create, got {reused['Domain']!r}"
    )
    assert reused["Id"] != original["Id"], (
        f"expected a freshly created monitor to get a new Id, not resurrect the deleted one {original['Id']!r}"
    )


def _safe_delete(rum, name):
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


def _wait_not_found(rum, name, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            rum.get_app_monitor(Name=name)
        except ClientError as exc:
            last = exc.response["Error"]["Code"]
            if last == "ResourceNotFoundException":
                return
        else:
            last = "no error"
        time.sleep(2.0)
    raise AssertionError(f"app monitor {name!r} was never fully deleted within {timeout_s}s; last saw {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
