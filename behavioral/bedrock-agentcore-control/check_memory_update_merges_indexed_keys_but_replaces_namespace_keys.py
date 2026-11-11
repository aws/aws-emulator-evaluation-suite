"""memory-update-merges-indexed-keys-but-replaces-namespace-keys."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# addIndexedKeys is additive ("Previously indexed keys cannot be removed") while namespaceKeys
# "fully replaces the existing set — any key you omit is removed" (UpdateMemory API reference);
# UpdateMemory can stay UPDATING for over 100 s, so the update leg polls up to 240 s.

CHECK = "memory-update-merges-indexed-keys-but-replaces-namespace-keys"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A single UpdateMemory applies additive-only semantics to addIndexedKeys and
    full-replacement semantics to namespaceKeys, proven by set algebra on an independent
    GetMemory."""
    bac = ctx.client("bedrock-agentcore-control")

    created_indexed = [
        {"key": "sim2real_alpha", "type": "STRING"},
        {"key": "sim2real_beta", "type": "NUMBER"},
    ]
    created_namespaces = [{"key": "alpha"}, {"key": "beta"}]

    name = _memory_name(ctx, "sim2realmergemem")
    create_resp = bac.create_memory(
        name=name,
        eventExpiryDuration=7,
        indexedKeys=created_indexed,
        namespaceKeys=created_namespaces,
        tags={"sim2real": CHECK},
    )
    memory_id = create_resp["memory"]["id"]
    ctx.on_cleanup(lambda: _ac_delete_memory(bac, memory_id))

    active = _poll_until(
        lambda: bac.get_memory(memoryId=memory_id)["memory"],
        lambda m: m["status"] in ("ACTIVE", "FAILED"),
        "the new memory to reach a terminal create status",
        timeout_s=300.0,
        interval_s=6.0,
    )
    assert active["status"] == "ACTIVE", (
        f"memory {memory_id} ended in {active['status']!r}: "
        f"failureReason={active.get('failureReason')!r}"
    )

    indexed_before = _key_set(active["indexedKeys"])
    namespaces_before = _key_set(active["namespaceKeys"])
    assert indexed_before == _key_set(created_indexed), (
        f"expected the memory to report the indexed keys it was created with "
        f"{sorted(_key_set(created_indexed))}, got {sorted(indexed_before)}"
    )
    assert namespaces_before == _key_set(created_namespaces), (
        f"expected the memory to report the namespace keys it was created with "
        f"{sorted(_key_set(created_namespaces))}, got {sorted(namespaces_before)}"
    )

    # ONE request, two fields, opposite semantics. An emulator that treats both as a merge, or
    # both as a replacement, fails one leg or the other — and no fixed HTTP transcript can
    # express the dependence on the pre-update set.
    added_indexed = [{"key": "sim2real_gamma", "type": "STRINGLIST"}]
    kept_namespace = [{"key": "alpha"}]
    dropped_namespace_key = "beta"
    assert dropped_namespace_key in namespaces_before, (
        f"premise broken: {dropped_namespace_key!r} is not in the pre-update namespace key set "
        f"{sorted(namespaces_before)}, so the replacement leg would assert nothing"
    )

    bac.update_memory(
        memoryId=memory_id,
        addIndexedKeys=added_indexed,
        namespaceKeys=kept_namespace,
    )
    settled = _poll_until(
        lambda: bac.get_memory(memoryId=memory_id)["memory"],
        lambda m: m["status"] in ("ACTIVE", "FAILED"),
        "the memory to leave UPDATING after the merge/replace update",
        timeout_s=240.0,
        interval_s=6.0,
    )
    assert settled["status"] == "ACTIVE", (
        f"memory {memory_id} ended in {settled['status']!r} after UpdateMemory: "
        f"failureReason={settled.get('failureReason')!r}"
    )

    indexed_after = _key_set(settled["indexedKeys"])
    namespaces_after = _key_set(settled["namespaceKeys"])

    # Additive: the exact set difference is what was added, and nothing was lost.
    expected_indexed = indexed_before | _key_set(added_indexed)
    assert indexed_after == expected_indexed, (
        f"addIndexedKeys must be additive: expected {sorted(expected_indexed)}, got "
        f"{sorted(indexed_after)} (lost {sorted(indexed_before - indexed_after)}, "
        f"unexpected {sorted(indexed_after - expected_indexed)})"
    )
    assert indexed_after - indexed_before == _key_set(added_indexed), (
        f"expected the indexed-key set to grow by exactly {sorted(_key_set(added_indexed))}, "
        f"it grew by {sorted(indexed_after - indexed_before)}"
    )

    # Replacement: the omitted key is GONE, and the set equals exactly what was sent.
    assert namespaces_after == _key_set(kept_namespace), (
        f"namespaceKeys must fully replace: expected exactly "
        f"{sorted(_key_set(kept_namespace))}, got {sorted(namespaces_after)}"
    )
    assert dropped_namespace_key not in namespaces_after, (
        f"namespace key {dropped_namespace_key!r} was omitted from UpdateMemory and must have "
        f"been removed, but the memory still reports {sorted(namespaces_after)}"
    )

    # The two fields must not have been treated the same way. Stated as its own assertion so a
    # target that merges both (or replaces both) names the exact confusion in its report.
    assert len(indexed_after) > len(indexed_before) and len(namespaces_after) < len(
        namespaces_before
    ), (
        f"expected one request to GROW indexedKeys and SHRINK namespaceKeys: indexed "
        f"{len(indexed_before)}->{len(indexed_after)}, namespaces "
        f"{len(namespaces_before)}->{len(namespaces_after)}"
    )

    # Freeze detector: three consecutive reads must return the same sets, so a target that
    # mutates on read cannot pass by luck.
    reads = []
    for _ in range(3):
        again = bac.get_memory(memoryId=memory_id)["memory"]
        reads.append(
            (tuple(sorted(_key_set(again["indexedKeys"]))), tuple(sorted(_key_set(again["namespaceKeys"]))))
        )
        time.sleep(2.0)
    assert len(set(reads)) == 1, (
        f"expected three consecutive GetMemory reads to agree, got {sorted(set(reads))}"
    )
    assert reads[0] == (
        tuple(sorted(expected_indexed)),
        tuple(sorted(_key_set(kept_namespace))),
    ), (
        f"expected the settled sets to be indexed={sorted(expected_indexed)} "
        f"namespaces={sorted(_key_set(kept_namespace))}, got {reads[0]}"
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


def _key_set(entries):
    """Hard-subscript: a missing 'key' member must fail loudly, not degrade to an empty set."""
    return {entry["key"] for entry in entries}


def _poll_until(probe, predicate, reason, timeout_s=240.0, interval_s=6.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {reason}; last value={last!r}")


def _memory_name(ctx, prefix):
    """Memory Name is ^[a-zA-Z][a-zA-Z0-9_]{0,47}$ — no hyphens."""
    raw = ctx.unique_name(f"{prefix}-")
    safe = "".join(c for c in raw if c.isalnum() or c == "_")
    if not safe[:1].isalpha():
        safe = "m" + safe
    return safe[:40]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
