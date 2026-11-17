"""memory-list-reflects-create-and-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "memory-list-reflects-create-and-delete"
GROUP = "state"
SERVICES = ["bedrock-agentcore-control"]


def _no_hyphen_name(ctx, prefix):
    raw = ctx.unique_name(f"{prefix}-")
    return "".join(ch for ch in raw if ch.isalnum() or ch == "_")[:40]


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")


def _list_all_memories(control):
    items = []
    token = None
    while True:
        kwargs = {"nextToken": token} if token else {}
        page = control.list_memories(**kwargs)
        items.extend(page.get("memories", []))
        token = page.get("nextToken")
        if not token:
            break
    return items


def _probe_get_memory(control, memory_id):
    """(kind, value): ("status", <memory status>) or ("gone", (<error code>, <message>))."""
    try:
        return ("status", control.get_memory(memoryId=memory_id)["memory"].get("status"))
    except ClientError as exc:
        return ("gone", (exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")))


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListMemories lists an ACTIVE memory exactly once with its arn, alongside a sibling created at
    the same time; after DeleteMemory and GetMemory answering ResourceNotFoundException, ListMemories
    no longer lists it while the sibling stays listed."""
    control = ctx.client("bedrock-agentcore-control")
    name_a = _no_hyphen_name(ctx, "sim2realmema")
    name_b = _no_hyphen_name(ctx, "sim2realmemb")

    created_a = control.create_memory(name=name_a, eventExpiryDuration=7)
    id_a = created_a["memory"]["id"]
    ctx.on_cleanup(lambda: _ac_delete_memory(control, id_a))

    created_b = control.create_memory(name=name_b, eventExpiryDuration=7)
    id_b = created_b["memory"]["id"]
    ctx.on_cleanup(lambda: _ac_delete_memory(control, id_b))

    final_a = _poll_until(
        lambda: control.get_memory(memoryId=id_a)["memory"],
        lambda m: m["status"] in ("ACTIVE", "FAILED"),
        timeout_s=300, interval_s=6,
        description=f"memory {id_a} settled",
    )
    assert final_a["status"] == "ACTIVE", (
        f"memory {id_a} ended in {final_a['status']!r}: {final_a.get('failureReason')!r}"
    )
    arn_a = final_a["arn"]

    final_b = _poll_until(
        lambda: control.get_memory(memoryId=id_b)["memory"],
        lambda m: m["status"] in ("ACTIVE", "FAILED"),
        timeout_s=300, interval_s=6,
        description=f"memory {id_b} settled",
    )
    assert final_b["status"] == "ACTIVE", (
        f"memory {id_b} ended in {final_b['status']!r}: {final_b.get('failureReason')!r}"
    )

    listed = _poll_until(
        lambda: _list_all_memories(control),
        lambda items: any(m.get("id") == id_a for m in items) and any(m.get("id") == id_b for m in items),
        timeout_s=60, interval_s=3,
        description=f"memories {id_a} and {id_b} both in ListMemories",
    )
    matches_a = [m for m in listed if m.get("id") == id_a]
    assert len(matches_a) == 1, f"expected exactly one summary for {id_a}, got {matches_a!r}"
    assert matches_a[0].get("status") == "ACTIVE", (
        f"expected ACTIVE in ListMemories for {id_a}, got {matches_a[0].get('status')!r}"
    )
    assert matches_a[0].get("arn") == arn_a, (
        f"expected arn {arn_a!r} in ListMemories for {id_a}, got {matches_a[0].get('arn')!r}"
    )
    assert any(m.get("id") == id_b for m in listed), (
        f"expected sibling {id_b} listed alongside {id_a}, got ids {[m.get('id') for m in listed]!r}"
    )

    control.delete_memory(memoryId=id_a)

    kind, value = _poll_until(
        lambda: _probe_get_memory(control, id_a),
        lambda kv: kv[0] == "gone",
        timeout_s=240, interval_s=6,
        description=f"GetMemory({id_a}) to answer ResourceNotFoundException",
    )
    code, message = value
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"Resource not found during GetMemory: Failed to retrieve memory item for ID: {id_a}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after = _poll_until(
        lambda: _list_all_memories(control),
        lambda items: not any(m.get("id") == id_a for m in items),
        timeout_s=60, interval_s=3,
        description=f"memory {id_a} removed from ListMemories",
    )
    assert not any(m.get("id") == id_a for m in after), f"deleted memory {id_a} still listed: {after!r}"
    assert any(m.get("id") == id_b for m in after), (
        f"expected sibling {id_b} still listed after deleting {id_a}, got ids {[m.get('id') for m in after]!r}"
    )


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
