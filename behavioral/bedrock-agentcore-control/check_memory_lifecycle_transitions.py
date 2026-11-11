"""memory-lifecycle-transitions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "memory-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Memory create->CREATING->ACTIVE, UpdateMemory is accepted while ACTIVE
    and returns to ACTIVE with the change persisted, and DeleteMemory makes
    GetMemory return ResourceNotFoundException."""
    bac = ctx.client("bedrock-agentcore-control")
    name = _safe_name(ctx, "sim2realmem")

    create_resp = bac.create_memory(name=name, eventExpiryDuration=7, tags={"sim2real": CHECK})
    memory_id = create_resp["memory"]["id"]
    ctx.on_cleanup(lambda: _ac_delete_memory(bac, memory_id))

    mem = _poll_until(
        lambda: bac.get_memory(memoryId=memory_id)["memory"],
        lambda m: m["status"] != "CREATING",
        timeout_s=170.0,
        interval_s=4.0,
    )
    assert mem["status"] == "ACTIVE", f"unexpected terminal status {mem['status']!r}"

    bac.update_memory(memoryId=memory_id, description="sim2real-updated-description")
    mem2 = _poll_until(
        lambda: bac.get_memory(memoryId=memory_id)["memory"],
        lambda m: m["status"] == "ACTIVE" and m["description"] == "sim2real-updated-description",
        timeout_s=220.0,
        interval_s=5.0,
    )
    assert mem2["status"] == "ACTIVE"
    assert mem2["description"] == "sim2real-updated-description"

    bac.delete_memory(memoryId=memory_id)
    code, message = _wait_rejected(
        lambda: bac.get_memory(memoryId=memory_id), timeout_s=240.0, interval_s=5.0
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"Resource not found during GetMemory: Failed to retrieve memory item for ID: {memory_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    mutate_code, mutate_message = _error(
        lambda: bac.update_memory(memoryId=memory_id, description="post-delete-should-fail")
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException mutating a deleted memory, got {mutate_code!r}"
    )
    expected_mutate = (
        f"Resource not found during UpdateMemory: Failed to retrieve memory item for ID: {memory_id}"
    )
    assert mutate_message == expected_mutate, (
        f"expected message {expected_mutate!r}, got {mutate_message!r}"
    )


# AgentCore refuses a delete while the resource is CREATING/UPDATING or still has dependents
# (ValidationException/ConflictException), and an accepted delete completes asynchronously. The
# runner swallows a cleanup's exception, so a bare delete in on_cleanup leaked even on PASS.
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


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; AssertionError if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")

def _wait_rejected(fn, *, timeout_s, interval_s=3.0):
    """Retry ``fn`` until it is rejected and return its (code, message); raise on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return _error(fn)
        except AssertionError:
            if time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _safe_name(ctx, prefix):
    raw = ctx.unique_name(prefix)
    cleaned = "".join(c for c in raw if c.isalnum() or c == "_")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "a" + cleaned
    return cleaned[:48]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
