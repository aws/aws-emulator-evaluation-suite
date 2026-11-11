"""capability-payload-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "capability-payload-round-trip"
GROUP = "data-plane"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A registered capability's name and applicationId read back unchanged via GetCapability, and
    GetCapability raises ResourceNotFoundException once DeregisterCapability completes.
    """
    client = ctx.client("opensearch")
    app_id = _create_active_application(ctx)
    capability_name = _capability_name(ctx)

    registered = client.register_capability(
        applicationId=app_id, capabilityName=capability_name, capabilityConfig={"aiConfig": {}}
    )
    assert registered["capabilityName"] == capability_name, (
        f"RegisterCapability echoed capabilityName={registered['capabilityName']!r}, expected {capability_name!r}"
    )
    assert registered["applicationId"] == app_id, (
        f"RegisterCapability echoed applicationId={registered['applicationId']!r}, expected {app_id!r}"
    )

    def _deregister():
        from botocore.exceptions import ClientError

        try:
            client.deregister_capability(applicationId=app_id, capabilityName=capability_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_deregister)

    _wait_capability_status(ctx, app_id, capability_name, {"active"}, {"create_failed"})

    got = client.get_capability(applicationId=app_id, capabilityName=capability_name)
    assert got["capabilityName"] == capability_name, f"capability name did not round-trip: {got!r}"
    assert got["applicationId"] == app_id, f"applicationId did not round-trip: {got!r}"

    got_again = client.get_capability(applicationId=app_id, capabilityName=capability_name)
    assert got_again["capabilityName"] == got["capabilityName"], (
        f"capabilityName changed between two consecutive reads: {got['capabilityName']!r} -> {got_again['capabilityName']!r}"
    )
    assert got_again["applicationId"] == got["applicationId"], (
        f"applicationId changed between two consecutive reads: {got['applicationId']!r} -> {got_again['applicationId']!r}"
    )

    client.deregister_capability(applicationId=app_id, capabilityName=capability_name)

    code, message = _poll_until_gone(ctx, app_id, capability_name, timeout_s=180.0)
    assert code == "ResourceNotFoundException", f"capability was not fully removed after deregister: {code!r}"
    expected = f"Capability {capability_name} not found for application {app_id}"
    assert message == expected, f"deregistered-capability message: expected {expected!r}, got {message!r}"


def _app_name(ctx) -> str:
    raw = ctx.unique_name("sim2real-cap-").lower().replace("_", "-")
    cleaned = "".join(ch for ch in raw if ch.isalnum() or ch == "-")
    if not cleaned[0].isalpha():
        cleaned = "a" + cleaned
    return cleaned[:30]


def _capability_name(ctx) -> str:
    # "ai-capability" is the fixed identifier for the AI Assistant capability; any other
    # capabilityName is rejected with ValidationException.
    return "ai-capability"


def _create_active_application(ctx) -> str:
    client = ctx.client("opensearch")
    name = _app_name(ctx)
    created = client.create_application(
        name=name, tagList=[{"Key": "sim2real-check", "Value": CHECK}]
    )
    app_id = created["id"]
    ctx.on_cleanup(lambda: client.delete_application(id=app_id))
    deadline = time.monotonic() + 600.0
    last = None
    while time.monotonic() < deadline:
        got = client.get_application(id=app_id)
        last = got.get("status")
        if last == "ACTIVE":
            return app_id
        if last == "FAILED":
            raise AssertionError(f"application {app_id} failed to become active: {got!r}")
        time.sleep(5)
    raise AssertionError(f"application {app_id} did not reach ACTIVE within 600s (last={last!r})")


def _wait_capability_status(ctx, app_id, capability_name, ok_statuses, terminal_bad_statuses, timeout_s=300.0):
    client = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        got = client.get_capability(applicationId=app_id, capabilityName=capability_name)
        last = got.get("status")
        if last in ok_statuses:
            return got
        if last in terminal_bad_statuses:
            raise AssertionError(f"capability {capability_name} reached bad status {last!r}: {got!r}")
        time.sleep(5)
    raise AssertionError(f"capability {capability_name} did not reach {ok_statuses} within {timeout_s}s (last={last!r})")


def _poll_until_gone(ctx, app_id, capability_name, timeout_s=180.0):
    """Poll GetCapability until it raises; return that (code, message). Still answering at the
    deadline fails the check."""
    from botocore.exceptions import ClientError

    client = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = client.get_capability(applicationId=app_id, capabilityName=capability_name)
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
        time.sleep(5)
    raise AssertionError(f"capability {capability_name} still readable {timeout_s}s after deregister: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
