"""update-memory-invalid-state-transition-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-memory-invalid-state-transition-rejected"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateMemory dropping a namespaceKey a strategy's namespaceTemplate still references is refused with
    ValidationException and the exact message, keeping the key; once the strategy is retargeted (with a description
    that lands too) the identical update succeeds and leaves only "unrelatedattr"."""
    client = ctx.client("bedrock-agentcore-control")
    name = _pattern_safe_name(ctx, "sim2realmemnsk")

    created = client.create_memory(
        name=name,
        eventExpiryDuration=7,
        namespaceKeys=[{"key": "customattr"}],
        memoryStrategies=[
            {
                "semanticMemoryStrategy": {
                    "name": "sim2realStrategy",
                    "namespaceTemplates": ["/custom/{customattr}/facts"],
                }
            }
        ],
        tags={"sim2real-check": CHECK},
    )
    memory_id = created["memory"]["id"]
    ctx.on_cleanup(lambda: _ac_delete_memory(client, memory_id))

    mem = _poll_memory_until_stable(client, memory_id, timeout_s=250.0)
    assert mem["status"] == "ACTIVE", f"unexpected terminal status {mem['status']!r}"
    strategy_id = mem["strategies"][0]["strategyId"]

    # Break: omitting "customattr" while the strategy's namespaceTemplate still
    # references it is a rejected state transition. Issued straight off a known-ACTIVE
    # memory (no unsettled mutation ahead of it), so a rejection here is the specific
    # validation, not real AWS's separate "still transitioning" guard.
    code, message = _error(
        lambda: client.update_memory(memoryId=memory_id, namespaceKeys=[{"key": "unrelatedattr"}])
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = (
        "Validation failed during UpdateMemory: [customattr] namespaceKeys are still in reference "
        "with existing strategies, please update the strategies before proceeding with this update"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: an independent read shows the original namespaceKeys untouched.
    mem_after_reject = client.get_memory(memoryId=memory_id)["memory"]
    keys_after_reject = {nk["key"] for nk in mem_after_reject.get("namespaceKeys", [])}
    assert "customattr" in keys_after_reject, f"customattr namespaceKey was dropped: {keys_after_reject}"

    # Restore: retarget the strategy so nothing references "customattr" any more, and
    # -- in the same call, since real AWS refuses a second UpdateMemory while the first
    # is still settling -- carry the positive-control's benign field too.
    client.update_memory(
        memoryId=memory_id,
        description="sim2real-updated-description",
        memoryStrategies={
            "modifyMemoryStrategies": [
                {"memoryStrategyId": strategy_id, "namespaceTemplates": ["/generic/facts"]}
            ]
        },
    )
    mem_retargeted = _poll_memory_until_stable(client, memory_id, timeout_s=250.0)
    assert mem_retargeted["status"] == "ACTIVE", (
        f"unexpected status after retargeting the strategy: {mem_retargeted['status']!r}"
    )
    assert mem_retargeted["description"] == "sim2real-updated-description", (
        f"benign description update did not stick: {mem_retargeted['description']!r}"
    )
    live_templates = {
        template
        for strategy in mem_retargeted["strategies"]
        for template in strategy.get("namespaceTemplates", [])
    }
    assert not any("{customattr}" in t for t in live_templates), (
        f"strategy still references customattr after retarget: {live_templates}"
    )

    # The identical call that was rejected a moment ago now succeeds: the block was
    # a live state dependency, not a permanent property of the input.
    client.update_memory(memoryId=memory_id, namespaceKeys=[{"key": "unrelatedattr"}])

    # Terminal read: independent, at the destination -- "customattr" is actually gone.
    mem_final = _poll_until(
        lambda: client.get_memory(memoryId=memory_id)["memory"],
        lambda m: {nk["key"] for nk in m.get("namespaceKeys", [])} == {"unrelatedattr"},
        timeout_s=60.0,
        interval_s=3.0,
    )
    keys_final = {nk["key"] for nk in mem_final.get("namespaceKeys", [])}
    assert keys_final == {"unrelatedattr"}, f"expected only unrelatedattr, got {keys_final}"


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


def _error(fn):
    """Return (code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _pattern_safe_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    safe = "".join(c for c in raw if c.isalnum() or c == "_")
    if not safe[:1].isalpha():
        safe = "m" + safe
    return safe[:48]


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _poll_memory_until_stable(client, memory_id: str, timeout_s: float):
    return _poll_until(
        lambda: client.get_memory(memoryId=memory_id)["memory"],
        lambda m: m["status"] not in ("CREATING", "UPDATING"),
        timeout_s=timeout_s,
        interval_s=4.0,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
