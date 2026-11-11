"""delete-memory-nonexistent-returns-resource-not-found."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-memory-nonexistent-returns-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteMemory on a nonexistent memory id returns ResourceNotFoundException, and a
    real memory is unaffected by (and still deletable after) the failed call."""
    client = ctx.client("bedrock-agentcore-control")

    real_name = _pattern_safe_name(ctx, "sim2realmemdel")
    created = client.create_memory(
        name=real_name,
        eventExpiryDuration=7,
        tags={"env": "sim2real-test", "purpose": "delete-memory-nonexistent-returns-resource-not-found"},
    )
    real_id = created["memory"]["id"]
    ctx.on_cleanup(lambda: _ac_delete_memory(client, real_id))

    # A well-formed but nonexistent memoryId (pattern: letters/digits/-/_ then '-' then 10 alnum chars).
    fake_id = f"{real_name}nonexist-{uuid.uuid4().hex[:10]}"

    code, message = _error_detail(lambda: client.delete_memory(memoryId=fake_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = (
        f"Resource not found during DeleteMemory: Failed to retrieve memory with ID: "
        f"{fake_id} for account: {ctx.account}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the real memory was not touched by the failed delete on a different id.
    got = client.get_memory(memoryId=real_id)
    assert got["memory"]["id"] == real_id, f"expected {real_id}, got {got['memory'].get('id')!r}"

    # Positive control: deleting the real memory by its real id succeeds -- but
    # DeleteMemory rejects a memory still in a transitional state, so poll until
    # the async create has actually settled (ACTIVE or FAILED) first.
    _poll_until(
        lambda: client.get_memory(memoryId=real_id)["memory"]["status"],
        lambda status: status != "CREATING",
        timeout_s=240.0,
    )
    del_resp = client.delete_memory(memoryId=real_id)
    assert del_resp["status"] == "DELETING", (
        f"expected DeleteMemory to start the delete, got {del_resp.get('status')!r}"
    )

    # The accepted delete is not just a response field -- it takes effect, visible on
    # independent reads at the destination: each read reports DELETING until the memory is gone.
    def _read_deleting():
        status = client.get_memory(memoryId=real_id)["memory"]["status"]
        assert status == "DELETING", f"expected DELETING on independent read after delete, got {status!r}"
        return status

    gone_code, gone_message = _poll_gone(_read_deleting, timeout_s=600.0)
    assert gone_code == "ResourceNotFoundException", (
        f"expected the deleted memory to read as ResourceNotFoundException, got {gone_code!r}"
    )
    expected_gone = (
        f"Resource not found during GetMemory: Failed to retrieve memory item for ID: {real_id}"
    )
    assert gone_message == expected_gone, f"expected message {expected_gone!r}, got {gone_message!r}"


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


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _error_detail(fn):
    """Return (code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_gone(read, timeout_s=300.0, interval_s=10.0):
    """Poll read() until it raises ClientError; return (code, message). Raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = read()
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
        time.sleep(interval_s)
    raise AssertionError(f"resource still readable after {timeout_s}s; last value={last!r}")


def _pattern_safe_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    safe = "".join(c for c in raw if c.isalnum() or c == "_")
    if not safe[:1].isalpha():
        safe = "m" + safe
    return safe[:48]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
