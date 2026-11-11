"""memory-lifecycle-and-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "memory-lifecycle-and-delete"
GROUP = "state"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateMemory reaches ACTIVE with its name and eventExpiryDuration 10; after DeleteMemory, GetMemory answers
    ResourceNotFoundException, and a second delete answers ResourceNotFoundException with the exact message naming
    the memory id and account."""
    control = ctx.client("bedrock-agentcore-control")
    name = _no_hyphen_name(ctx, "sim2realmem")

    create_resp = control.create_memory(name=name, eventExpiryDuration=10)
    memory_id = create_resp["memory"]["id"]
    ctx.on_cleanup(lambda: _ac_delete_memory(control, memory_id))

    final = _poll_until(
        lambda: control.get_memory(memoryId=memory_id)["memory"],
        lambda m: m["status"] in ("ACTIVE", "FAILED"),
        timeout_s=300,
        interval_s=6,
    )
    assert final["status"] == "ACTIVE", f"memory ended in {final['status']!r}: {final.get('failureReason')}"
    assert final["name"] == name, f"expected name {name!r}, got {final['name']!r}"
    assert final["eventExpiryDuration"] == 10, f"expected eventExpiryDuration 10, got {final['eventExpiryDuration']!r}"

    control.delete_memory(memoryId=memory_id)
    _wait_gone_memory(control, memory_id, timeout_s=240, interval_s=6)

    code, message = _error(lambda: control.delete_memory(memoryId=memory_id))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException deleting a gone memory, got {code!r}"
    )
    expected = (
        f"Resource not found during DeleteMemory: Failed to retrieve memory with ID: "
        f"{memory_id} for account: {ctx.account}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


# AgentCore refuses a delete while the resource is CREATING/UPDATING or still has dependents
# (ValidationException/ConflictException), and an accepted delete completes asynchronously, so a
# teardown waits out transitional statuses and then for the resource to be gone.
_AC_TRANSITIONAL = ("CREATING", "UPDATING", "DELETING", "SYNCHRONIZING")


def _ac_delete_and_wait(get_status, delete, *, what, timeout_s=600.0, interval_s=5.0):
    """Delete once out of a transitional status, then wait for ResourceNotFound; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            last = get_status()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if last == "DELETED":
            return
        if last not in _AC_TRANSITIONAL:
            try:
                delete()
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code not in ("ConflictException", "ValidationException"):
                    raise
                last = f"{last}; delete refused: {exc}"
        if time.monotonic() >= deadline:
            raise AssertionError(f"teardown: {what} still present after {timeout_s}s ({last})")
        time.sleep(interval_s)


def _ac_delete_memory(control, memory_id):
    _ac_delete_and_wait(
        lambda: control.get_memory(memoryId=memory_id)["memory"]["status"],
        lambda: control.delete_memory(memoryId=memory_id),
        what=f"memory {memory_id}",
    )


def _no_hyphen_name(ctx, prefix):
    raw = ctx.unique_name(f"{prefix}-")
    sanitized = "".join(ch for ch in raw if ch.isalnum() or ch == "_")
    return sanitized[:40]


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; AssertionError if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _wait_gone_memory(control, memory_id, *, timeout_s=120.0, interval_s=3.0):
    # MemoryStatus has no terminal DELETED value (CREATING/ACTIVE/FAILED/DELETING/UPDATING),
    # so DELETING is transitional, not gone -- the only proof of deletion is
    # ResourceNotFoundException on an independent read.
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            resp = control.get_memory(memoryId=memory_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        last_status = resp["memory"].get("status")
        time.sleep(interval_s)
    raise AssertionError(f"memory did not disappear within {timeout_s}s; last status={last_status!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
