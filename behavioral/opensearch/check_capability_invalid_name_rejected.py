"""capability-invalid-name-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "capability-invalid-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterCapability rejects a well-formed capabilityName other than ``ai-capability`` with
    ValidationException and creates nothing; the same application accepts ``ai-capability``.
    """
    client = ctx.client("opensearch")
    app_id = _create_active_application(ctx)
    bogus_name = "not-ai-capability"

    code, message = _client_error(
        lambda: client.register_capability(
            applicationId=app_id, capabilityName=bogus_name, capabilityConfig={"aiConfig": {}}
        )
    )
    assert code == "ValidationException", f"expected ValidationException for invalid capability name, got {code!r}"
    expected = f"Invalid capability name for AI Capability: {bogus_name}. Only ai-capability is allowed"
    assert message == expected, f"invalid-name message: expected {expected!r}, got {message!r}"

    # Effect absent: no capability record was created under the rejected name.
    not_found_code, not_found_message = _client_error(
        lambda: client.get_capability(applicationId=app_id, capabilityName=bogus_name)
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"expected no capability to exist under the rejected name, got {not_found_code!r}"
    )
    expected = f"Capability {bogus_name} not found for application {app_id}"
    assert not_found_message == expected, (
        f"missing-capability message: expected {expected!r}, got {not_found_message!r}"
    )

    # Positive control: the SAME application accepts the correct fixed identifier.
    client.register_capability(
        applicationId=app_id, capabilityName="ai-capability", capabilityConfig={"aiConfig": {}}
    )
    ctx.on_cleanup(lambda: _best_effort_deregister(ctx, app_id, "ai-capability"))
    ok = _wait_capability_status(ctx, app_id, "ai-capability", {"active"}, {"create_failed"})
    assert ok["capabilityName"] == "ai-capability", (
        f"expected the correctly-named capability to reach active status, got {ok!r}"
    )


def _app_name(ctx) -> str:
    raw = ctx.unique_name("sim2real-capdup-").lower().replace("_", "-")
    cleaned = "".join(ch for ch in raw if ch.isalnum() or ch == "-")
    if not cleaned[0].isalpha():
        cleaned = "a" + cleaned
    return cleaned[:30]


def _client_error(fn):
    """(code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_active_application(ctx) -> str:
    client = ctx.client("opensearch")
    name = _app_name(ctx)
    created = client.create_application(name=name)
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


def _best_effort_deregister(ctx, app_id, capability_name):
    client = ctx.client("opensearch")
    try:
        client.deregister_capability(applicationId=app_id, capabilityName=capability_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
