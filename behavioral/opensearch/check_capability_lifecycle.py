"""capability-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "capability-lifecycle"
GROUP = 'application'
SERVICES = ['opensearch']


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=6.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _status_or_error_code(osc, app_id, capability_name):
    """The capability's status while GetCapability answers, else the error code it raises."""
    try:
        return osc.get_capability(applicationId=app_id, capabilityName=capability_name)["status"]
    except ClientError as exc:
        return exc.response["Error"]["Code"]


def _deregister_if_present(osc, app_id, capability_name):
    """Teardown that tolerates a capability the check already deregistered."""
    try:
        osc.deregister_capability(applicationId=app_id, capabilityName=capability_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterCapability->GetCapability->DeregisterCapability cycle on an
    Application; GetCapability after deregistration raises
    ResourceNotFoundException."""
    osc = ctx.client("opensearch")
    app_name = ctx.unique_name("sim2real-behav-app-")[:30].rstrip("-")
    created_app = osc.create_application(name=app_name)
    app_id = created_app["id"]
    ctx.on_cleanup(lambda: osc.delete_application(id=app_id))
    _poll_until(
        lambda: osc.get_application(id=app_id),
        lambda a: a.get("status") in ("ACTIVE", "FAILED"),
        timeout_s=180,
        description=f"application {app_id} active",
    )

    capability_name = "ai-capability"
    registered = osc.register_capability(
        applicationId=app_id,
        capabilityName=capability_name,
        capabilityConfig={"aiConfig": {}},
    )
    ctx.on_cleanup(lambda: _deregister_if_present(osc, app_id, capability_name))
    assert registered["applicationId"] == app_id, (
        f"expected applicationId {app_id!r}, got {registered.get('applicationId')!r}"
    )
    assert registered["capabilityName"] == capability_name, (
        f"expected capabilityName {capability_name!r}, got {registered.get('capabilityName')!r}"
    )
    assert registered["status"] in ("creating", "active", "create_failed"), (
        f"unexpected initial capability status {registered.get('status')!r}"
    )

    settled = _poll_until(
        lambda: osc.get_capability(applicationId=app_id, capabilityName=capability_name),
        lambda c: c.get("status") in ("active", "create_failed"),
        timeout_s=180,
        description=f"capability {capability_name}/{app_id} active",
    )
    assert settled["status"] == "active", f"capability failed to become active: {settled}"

    got = osc.get_capability(applicationId=app_id, capabilityName=capability_name)
    assert got["capabilityName"] == capability_name, (
        f"expected capabilityName {capability_name!r}, got {got.get('capabilityName')!r}"
    )
    assert got["status"] == "active", f"expected status 'active', got {got.get('status')!r}"

    deregistered = osc.deregister_capability(applicationId=app_id, capabilityName=capability_name)
    assert deregistered["status"] in ("deleting", "delete_failed"), (
        f"unexpected deregister status {deregistered.get('status')!r}"
    )

    _poll_until(
        lambda: _status_or_error_code(osc, app_id, capability_name),
        lambda state: state == "ResourceNotFoundException",
        timeout_s=120,
        interval_s=2.0,
        description=f"capability {capability_name}/{app_id} deregistered",
    )
    try:
        still = osc.get_capability(applicationId=app_id, capabilityName=capability_name)
    except ClientError as exc:
        message = exc.response["Error"].get("Message", "")
    else:
        raise AssertionError(f"GetCapability answered after not-found was observed: {still!r}")
    expected = f"Capability {capability_name} not found for application {app_id}"
    assert message == expected, f"deregistered-capability message: expected {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
