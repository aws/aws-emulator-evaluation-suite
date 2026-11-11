"""memory-record-unicode-content-round-trip."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "memory-record-unicode-content-round-trip"
GROUP = "server-side"
SERVICES = ["bedrock-agentcore"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Unicode text written via BatchCreateMemoryRecords is returned byte-identical by GetMemoryRecord."""
    control = ctx.client("bedrock-agentcore-control")
    data = ctx.client("bedrock-agentcore")

    mem_name = _sanitized_control_name(ctx, "sim2realmem")
    actor_id = "test-actor"
    strategy_name = "UserPrefStrategy"
    namespace = f"/users/{actor_id}/preferences/"

    created = control.create_memory(
        name=mem_name,
        description="sim2real behavioral fidelity check: unicode content round trip",
        eventExpiryDuration=7,
        memoryStrategies=[
            {
                "userPreferenceMemoryStrategy": {
                    "name": strategy_name,
                    "namespaceTemplates": [namespace],
                }
            }
        ],
        tags={"sim2real": CHECK},
    )
    memory_id = created["memory"]["id"]
    ctx.on_cleanup(lambda: _ac_delete_memory(control, memory_id))

    memory = _wait_for_memory_active(control, memory_id, timeout_s=300.0, interval_s=10.0)
    strategy_id = None
    for strategy in memory.get("strategies", []):
        if strategy.get("name") == strategy_name:
            strategy_id = strategy["strategyId"]
            break
    assert strategy_id is not None, "expected the userPreferenceMemoryStrategy to be provisioned"

    # Mix of CJK, RTL, Latin-with-diacritics, Greek, and an emoji to exercise multi-byte UTF-8
    # encoding paths that a naive byte-copy or truncating storage layer would corrupt.
    unicode_text = "こんにちは世界 🎉 café Ñoño مرحبا بالعالم δοκιμή — ẞaß"
    request_id = _sanitized_control_name(ctx, "req")

    created_records = data.batch_create_memory_records(
        memoryId=memory_id,
        records=[
            {
                "requestIdentifier": request_id,
                "namespaces": [namespace],
                "content": {"text": unicode_text},
                "timestamp": datetime.now(timezone.utc),
                "memoryStrategyId": strategy_id,
            }
        ],
    )
    assert created_records["failedRecords"] == [], created_records["failedRecords"]
    successful = created_records["successfulRecords"]
    assert len(successful) == 1, f"expected exactly 1 successful record, got {successful!r}"
    assert successful[0]["status"] == "SUCCEEDED", (
        f"expected status SUCCEEDED, got {successful[0]['status']!r}"
    )
    record_id = successful[0]["memoryRecordId"]

    fetched = data.get_memory_record(memoryId=memory_id, memoryRecordId=record_id)
    fetched_text = fetched["memoryRecord"]["content"]["text"]
    assert fetched_text == unicode_text, (
        f"unicode content changed on read-back: wrote {unicode_text!r}, read {fetched_text!r}"
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

def _sanitized_control_name(ctx, prefix: str) -> str:
    """CreateMemory names/requestIdentifiers reject hyphens; ctx.unique_name emits them."""
    raw = ctx.unique_name(prefix)
    cleaned = "".join(c for c in raw if c.isalnum() or c == "_")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "a" + cleaned
    return cleaned[:48]


def _wait_for_memory_active(control, memory_id, *, timeout_s=300.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = control.get_memory(memoryId=memory_id)
        memory = resp["memory"]
        status = memory.get("status")
        if status == "ACTIVE":
            return memory
        if status in ("CREATE_FAILED", "FAILED"):
            raise AssertionError(f"memory {memory_id} entered terminal failure status {status}")
        time.sleep(interval_s)
    raise AssertionError(f"memory {memory_id} did not become ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
