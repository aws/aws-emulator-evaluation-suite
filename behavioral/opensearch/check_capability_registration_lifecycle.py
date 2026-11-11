"""capability-registration-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "capability-registration-lifecycle"
GROUP = "state-machine"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterCapability -> GetCapability -> DeregisterCapability state machine on an application."""
    osv = ctx.client("opensearch")
    app_id = _create_application(ctx)

    reg = osv.register_capability(
        applicationId=app_id,
        capabilityName="ai-capability",
        capabilityConfig={"aiConfig": {}},
    )
    assert reg["applicationId"] == app_id
    assert reg["capabilityName"] == "ai-capability"

    status = _poll_capability_status(
        osv, app_id, "ai-capability", {"active", "create_failed"}, timeout_s=300
    )
    assert status == "active", f"capability landed in {status!r} instead of active"

    got = osv.get_capability(applicationId=app_id, capabilityName="ai-capability")
    assert got["applicationId"] == app_id
    assert got["capabilityName"] == "ai-capability"
    assert got["status"] == "active"

    dereg = osv.deregister_capability(applicationId=app_id, capabilityName="ai-capability")
    assert dereg["status"] in ("deleting", "delete_failed")

    deadline = time.monotonic() + 180
    state = None
    while time.monotonic() < deadline:
        state = _status_or_error_code(osv, app_id, "ai-capability")
        if state == "ResourceNotFoundException":
            break
        time.sleep(5)
    assert state == "ResourceNotFoundException", (
        f"capability still resolvable after deregistration (last state={state!r})"
    )
    code, message = _client_error(
        lambda: osv.get_capability(applicationId=app_id, capabilityName="ai-capability")
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"Capability ai-capability not found for application {app_id}"
    assert message == expected, f"deregistered-capability message: expected {expected!r}, got {message!r}"

    redereg_code, redereg_message = _client_error(
        lambda: osv.deregister_capability(applicationId=app_id, capabilityName="ai-capability")
    )
    assert redereg_code == "ResourceNotFoundException", (
        f"deregistering an already-gone capability should fail not-found, got code={redereg_code!r}"
    )
    expected = f"Capability ai-capability not found for application {app_id}"
    assert redereg_message == expected, (
        f"repeat-deregister message: expected {expected!r}, got {redereg_message!r}"
    )


def _create_application(ctx) -> str:
    osv = ctx.client("opensearch")
    name = ctx.unique_name("sim2real-app-")
    resp = osv.create_application(
        name=name, tagList=[{"Key": "sim2real", "Value": "capability-registration-lifecycle"}]
    )
    app_id = resp["id"]
    ctx.on_cleanup(lambda: _safe_delete_application(osv, app_id))
    _wait_application_active(osv, app_id, timeout_s=300)
    return app_id


def _wait_application_active(osv, app_id: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = osv.get_application(id=app_id)["status"]
        if last == "ACTIVE":
            return
        if last == "FAILED":
            raise AssertionError(f"application {app_id} entered FAILED state while waiting for ACTIVE")
        time.sleep(interval_s)
    raise AssertionError(f"application {app_id} did not reach ACTIVE within {timeout_s}s (last={last})")


def _poll_capability_status(osv, app_id: str, name: str, terminal: set[str], timeout_s: float = 300.0, interval_s: float = 5.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = osv.get_capability(applicationId=app_id, capabilityName=name)["status"]
        if last in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"capability {name} on {app_id} did not reach {terminal} within {timeout_s}s (last={last})")


def _safe_delete_application(osv, app_id: str) -> None:
    try:
        osv.delete_application(id=app_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _client_error(fn):
    """(code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _status_or_error_code(osv, app_id: str, name: str) -> str:
    """The capability's status while GetCapability answers, else the error code it raises."""
    try:
        return osv.get_capability(applicationId=app_id, capabilityName=name)["status"]
    except ClientError as err:
        return err.response["Error"]["Code"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
