"""memory-record-lifecycle."""
from __future__ import annotations

import datetime as _dt
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "memory-record-lifecycle"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchCreateMemoryRecords produces records retrievable via GetMemoryRecord, and
    DeleteMemoryRecord removes them causing subsequent gets AND a second delete on the same
    id to ResourceNotFoundException."""
    control = ctx.client("bedrock-agentcore-control")
    data = ctx.client("bedrock-agentcore")

    memory_id = _create_memory(ctx, control)
    namespace = "/sim2real-test"

    def _try_create():
        try:
            return data.batch_create_memory_records(
                memoryId=memory_id,
                records=[
                    {
                        "requestIdentifier": "sim2real-record-1",
                        "namespaces": [namespace],
                        "content": {"text": "The customer's favorite color is teal."},
                        "timestamp": _dt.datetime.now(_dt.timezone.utc),
                    }
                ],
            )
        except Exception as exc:
            if "not active" in str(exc):
                return None
            raise

    # The memory resource can report status=ACTIVE from GetMemory slightly before the
    # data plane is actually ready to accept writes against it; retry through that gap.
    created = _poll_until(_try_create, lambda r: r is not None, timeout_s=90.0, interval_s=5.0)
    assert created["failedRecords"] == [], f"expected no failed records, got {created['failedRecords']!r}"
    assert len(created["successfulRecords"]) == 1, (
        f"expected exactly 1 successful record, got {len(created['successfulRecords'])}"
    )
    record_id = created["successfulRecords"][0]["memoryRecordId"]

    got = data.get_memory_record(memoryId=memory_id, memoryRecordId=record_id)
    assert got["memoryRecord"]["memoryRecordId"] == record_id, (
        f"expected memoryRecordId {record_id!r}, got {got['memoryRecord']['memoryRecordId']!r}"
    )
    assert got["memoryRecord"]["content"]["text"] == "The customer's favorite color is teal.", (
        f"expected the written text back verbatim, got {got['memoryRecord']['content']['text']!r}"
    )
    assert got["memoryRecord"]["namespaces"], "expected a non-empty namespaces list on the created record"

    data.delete_memory_record(memoryId=memory_id, memoryRecordId=record_id)

    code, message = _error(lambda: data.get_memory_record(memoryId=memory_id, memoryRecordId=record_id))
    assert code == "ResourceNotFoundException", (
        f"expected GetMemoryRecord on a deleted record to fail with ResourceNotFoundException, got {code!r}"
    )
    assert message == "The memory record was not found", (
        f"expected message 'The memory record was not found', got {message!r}"
    )

    # The delete is a mutation, not just a state fact: a second delete on the same dead id
    # must fail too, proving DeleteMemoryRecord itself enforces the same not-found precondition
    # rather than merely leaving GetMemoryRecord to notice.
    redelete_code, redelete_message = _error(lambda: data.delete_memory_record(memoryId=memory_id, memoryRecordId=record_id))
    assert redelete_code == "ResourceNotFoundException", (
        f"expected a second DeleteMemoryRecord on an already-deleted id to fail with "
        f"ResourceNotFoundException, got {redelete_code!r}"
    )
    assert redelete_message == "The memory record was not found", (
        f"expected message 'The memory record was not found', got {redelete_message!r}"
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
def _create_memory(ctx, control) -> str:
    name = "sim2realmem" + ctx.unique_name("x").replace("-", "")[:36]
    try:
        resp = control.create_memory(name=name, eventExpiryDuration=7)
    except Exception as exc:  # pragma: no cover - defensive against control-plane drift
        raise AssertionError(
            f"CreateMemory (bedrock-agentcore-control) failed during setup: {exc!r}. "
            "Requires the bedrock-agentcore-control API to be reachable and permitted."
        ) from exc
    memory_arn = resp["memory"]["arn"]
    memory_id = memory_arn.rsplit("/", 1)[-1]

    ctx.on_cleanup(lambda: _ac_delete_memory(control, memory_id))

    # GetMemory's own status can still read CREATING past this deadline on a slow control
    # plane; that is not a failure — _try_create's "not active" retry below is what actually
    # gates on data-plane readiness, so a lingering CREATING here is left for it to resolve.
    # Only a genuine terminal failure status is raised here.
    deadline = time.monotonic() + 120.0
    status = resp["memory"].get("status")
    while status == "CREATING" and time.monotonic() < deadline:
        time.sleep(3.0)
        described = control.get_memory(memoryId=memory_id)
        status = described["memory"].get("status")
    if status not in ("ACTIVE", "CREATING", None):
        raise AssertionError(f"Memory resource entered status={status!r} instead of ACTIVE")
    return memory_id


def _error(fn):
    """Call fn() and return its ClientError (code, message). An unexpected SUCCESS raises rather
    than returning a falsy sentinel."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
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
