"""delete-app-monitor-wrong-state-after-delete-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-app-monitor-wrong-state-after-delete-rejected"
GROUP = "overly-permissive"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting an app monitor a second time, after it has already been deleted, fails with
    ResourceNotFoundException instead of returning a false success -- and the monitor is
    confirmed gone via GetAppMonitor too."""
    rum = ctx.client("rum")
    app_name = ctx.unique_name("sim2real-rum-delstate-")
    rum.create_app_monitor(
        Name=app_name,
        Domain="sim2real-behav.example.com",
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-rum-delstate"},
    )
    ctx.on_cleanup(lambda: _safe_delete_app_monitor(rum, app_name))

    # Positive control: deleting an existing app monitor succeeds.
    rum.delete_app_monitor(Name=app_name)

    # Break exactly one thing: delete an already-deleted app monitor.
    expected_message = f"Resource not found {app_name}"
    code, message = _client_error(lambda: rum.delete_app_monitor(Name=app_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect confirmed absent: the monitor is truly gone, not partially resurrected.
    get_code, get_message = _client_error(lambda: rum.get_app_monitor(Name=app_name))
    assert get_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {get_code!r}"
    assert get_message == expected_message, f"expected message {expected_message!r}, got {get_message!r}"


def _safe_delete_app_monitor(rum, name: str) -> None:
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
