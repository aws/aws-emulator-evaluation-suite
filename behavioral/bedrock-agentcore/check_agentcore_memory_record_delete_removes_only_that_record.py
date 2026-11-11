"""agentcore-memory-record-delete-removes-only-that-record."""
from __future__ import annotations

import datetime as _dt
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "agentcore-memory-record-delete-removes-only-that-record"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Deleting one memory record removes exactly that record from ListMemoryRecords while a sibling
    record in the same namespace survives, and GetMemoryRecord on it returns
    ResourceNotFoundException ('The memory record was not found').
    """
    control = ctx.client("bedrock-agentcore-control")
    data = ctx.client("bedrock-agentcore")

    memory_id = _create_memory(ctx, control)
    namespace = "/sim2real-test"

    keep_id, delete_id = _create_two_records(ctx, data, memory_id, namespace)

    # ListMemoryRecords lags BatchCreateMemoryRecords by an indexing delay, so poll for both ids
    # to appear.
    _poll_until(
        ctx,
        lambda: _list_record_ids(data, memory_id, namespace),
        lambda ids: keep_id in ids and delete_id in ids,
        timeout_s=60.0,
    )

    data.delete_memory_record(memoryId=memory_id, memoryRecordId=delete_id)

    after = _poll_until(
        ctx,
        lambda: _list_record_ids(data, memory_id, namespace),
        lambda ids: delete_id not in ids,
        timeout_s=60.0,
    )
    assert delete_id not in after, (
        f"deleted record {delete_id} is still present in ListMemoryRecords: {after!r}"
    )
    assert keep_id in after, (
        f"surviving record {keep_id} vanished from ListMemoryRecords after an unrelated "
        f"record's delete -- the list emptied entirely instead of removing only the "
        f"deleted record: {after!r}"
    )

    code, message = _error_code(lambda: data.get_memory_record(memoryId=memory_id, memoryRecordId=delete_id))
    assert code == "ResourceNotFoundException", (
        f"GetMemoryRecord on the deleted id returned {code!r}, expected ResourceNotFoundException"
    )
    assert message == "The memory record was not found", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {message!r}"
    )


# AgentCore refuses a delete while the resource is CREATING/UPDATING or still has dependents
# (ValidationException/ConflictException), and an accepted delete completes asynchronously, so a
# teardown waits out the transitional status and then for ResourceNotFoundException.
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


def _create_memory(ctx, control: Any) -> str:
    name = "sim2realmem" + ctx.unique_name("x").replace("-", "")[:36]
    try:
        resp = control.create_memory(name=name, eventExpiryDuration=7, tags={"sim2real-check": CHECK})
    except ClientError as exc:  # pragma: no cover - defensive against control-plane drift
        raise AssertionError(
            f"CreateMemory (bedrock-agentcore-control) failed during setup: {exc!r}"
        ) from exc
    memory_arn = resp["memory"]["arn"]
    memory_id = memory_arn.rsplit("/", 1)[-1]

    ctx.on_cleanup(lambda: _ac_delete_memory(control, memory_id))

    # A new memory can stay CREATING for several minutes before it turns ACTIVE.
    status = resp["memory"].get("status")
    deadline = time.monotonic() + min(600.0, ctx.time_left())
    while status == "CREATING" and time.monotonic() < deadline:
        time.sleep(2.0)
        status = control.get_memory(memoryId=memory_id)["memory"].get("status")
    assert status == "ACTIVE", f"Memory resource is in status={status!r}, not ACTIVE"
    return memory_id


def _create_two_records(ctx, data: Any, memory_id: str, namespace: str) -> tuple[str, str]:
    def _try_create():
        try:
            return data.batch_create_memory_records(
                memoryId=memory_id,
                records=[
                    {
                        "requestIdentifier": "sim2real-record-keep",
                        "namespaces": [namespace],
                        "content": {"text": "The customer's favorite color is teal."},
                        "timestamp": _dt.datetime.now(_dt.timezone.utc),
                    },
                    {
                        "requestIdentifier": "sim2real-record-delete",
                        "namespaces": [namespace],
                        "content": {"text": "The customer's shipping address changed."},
                        "timestamp": _dt.datetime.now(_dt.timezone.utc),
                    },
                ],
            )
        except ClientError as exc:
            if "not active" in str(exc).lower():
                return None
            raise

    # The memory resource can report status=ACTIVE from GetMemory slightly before the
    # data plane is actually ready to accept writes against it; retry through that gap.
    created = _poll_until(ctx, _try_create, lambda r: r is not None, timeout_s=90.0, interval_s=2.0)
    assert created["failedRecords"] == [], f"unexpected failed records: {created['failedRecords']!r}"
    by_request = {r["requestIdentifier"]: r["memoryRecordId"] for r in created["successfulRecords"]}
    assert set(by_request) == {"sim2real-record-keep", "sim2real-record-delete"}, (
        f"expected both requested records to succeed, got {by_request!r}"
    )
    return by_request["sim2real-record-keep"], by_request["sim2real-record-delete"]


def _list_record_ids(data: Any, memory_id: str, namespace: str) -> set[str]:
    ids: set[str] = set()
    next_token = None
    while True:
        kwargs: dict[str, Any] = dict(memoryId=memory_id, namespace=namespace, maxResults=100)
        if next_token:
            kwargs["nextToken"] = next_token
        resp = data.list_memory_records(**kwargs)
        ids.update(s["memoryRecordId"] for s in resp["memoryRecordSummaries"])
        next_token = resp.get("nextToken")
        if not next_token:
            return ids


def _error_code(fn) -> tuple[str, str]:
    """The (code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(ctx, probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + min(timeout_s, ctx.time_left())
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
