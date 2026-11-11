"""batch-create-memory-records-client-token-is-idempotent."""
from __future__ import annotations

import datetime as _dt
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-create-memory-records-client-token-is-idempotent"
GROUP = "concurrency"
SERVICES = ["bedrock-agentcore"]


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:negative-classes",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A replayed BatchCreateMemoryRecords carrying the same clientToken stores no duplicate,
    while the identical payload under a fresh clientToken does store a second record — so the
    deduplication is keyed on the token rather than on the content or on refusing all writes."""
    control = ctx.client("bedrock-agentcore-control")
    data = ctx.client("bedrock-agentcore")

    memory_id = _create_active_memory(ctx, control)

    tenant = ctx.unique_name("").replace("-", "")
    namespace = f"/simparity/{tenant}/idempotency/"
    text = f"idempotent-fact-{tenant}"
    timestamp = _dt.datetime.now(_dt.timezone.utc)
    records = [
        {
            "requestIdentifier": "simparity-idem-1",
            "namespaces": [namespace],
            "content": {"text": text},
            "timestamp": timestamp,
        }
    ]
    token = str(uuid.uuid4())

    first = _poll_until(
        lambda: _batch_create_through_activation_gap(data, memory_id, records, token),
        lambda r: r is not None,
        timeout_s=45.0,
        interval_s=5.0,
        description="BatchCreateMemoryRecords accepted by the freshly-created memory",
    )
    assert first["failedRecords"] == [], (
        f"the first batch reported failedRecords {first['failedRecords']!r}"
    )
    assert len(first["successfulRecords"]) == 1, (
        f"the first batch reported {len(first['successfulRecords'])} successful records, "
        f"expected 1: {first['successfulRecords']!r}"
    )
    original_id = first["successfulRecords"][0]["memoryRecordId"]

    _poll_until(
        lambda: _listed_ids(data, memoryId=memory_id, namespace=namespace),
        lambda ids: ids == {original_id},
        timeout_s=30.0,
        interval_s=3.0,
        description=f"record {original_id} became the sole record under {namespace}",
    )

    # The idempotent replay: byte-identical request, same clientToken.
    replay = data.batch_create_memory_records(
        memoryId=memory_id, records=records, clientToken=token
    )
    assert replay["failedRecords"] == [], (
        "the idempotent replay reported failures rather than being absorbed: "
        f"{replay['failedRecords']!r}"
    )

    # The load-bearing assertion: exactly one record still exists. Expressed as a set so the
    # failure names the duplicate ids rather than a bare count.
    after_replay = _listed_ids(data, memoryId=memory_id, namespace=namespace)
    assert after_replay == {original_id}, (
        f"after replaying the same batch with the same clientToken {token!r}, namespace "
        f"{namespace!r} holds {sorted(after_replay)!r}; expected still exactly "
        f"[{original_id!r}]. A target that ignores clientToken stores a duplicate here"
    )
    # The idempotent replay also returns the original id, asserted separately from the count.
    replayed_ids = [r["memoryRecordId"] for r in replay["successfulRecords"]]
    assert replayed_ids == [original_id], (
        f"the idempotent replay returned memoryRecordIds {replayed_ids!r}, expected the original "
        f"[{original_id!r}]"
    )

    # The positive control that makes the count assertion mean something: the SAME content under a
    # FRESH token is a genuinely new write. Without this, "one record" is indistinguishable from a
    # store that refuses everything after the first write.
    fresh_token = str(uuid.uuid4())
    assert fresh_token != token, "the two client tokens must differ"
    second = data.batch_create_memory_records(
        memoryId=memory_id, records=records, clientToken=fresh_token
    )
    assert second["failedRecords"] == [], (
        f"the fresh-token batch reported failedRecords {second['failedRecords']!r}"
    )
    assert len(second["successfulRecords"]) == 1, (
        f"the fresh-token batch reported {len(second['successfulRecords'])} successful records, "
        f"expected 1: {second['successfulRecords']!r}"
    )
    second_id = second["successfulRecords"][0]["memoryRecordId"]
    assert second_id != original_id, (
        f"the fresh-token write returned the original id {original_id!r}; a new clientToken must "
        "not be deduplicated against a previous one, or the token is being ignored in the other "
        "direction"
    )
    both = _poll_until(
        lambda: _listed_ids(data, memoryId=memory_id, namespace=namespace),
        lambda ids: ids == {original_id, second_id},
        timeout_s=30.0,
        interval_s=3.0,
        description=f"namespace {namespace} holds both records after the fresh-token write",
    )
    assert both == {original_id, second_id}, (
        f"namespace {namespace!r} holds {sorted(both)!r}, expected exactly "
        f"{sorted({original_id, second_id})!r}"
    )

    # The check already has to delete what it created, so the delete is asserted: gone by an
    # independent read, a mutation on the dead id refused, and the effect absent from the list —
    # while the twin survives, proving the delete was scoped.
    data.delete_memory_record(memoryId=memory_id, memoryRecordId=second_id)
    code, message = _error(
        lambda: data.get_memory_record(memoryId=memory_id, memoryRecordId=second_id)
    )
    assert code == "ResourceNotFoundException", (
        f"GetMemoryRecord on the deleted record {second_id!r} returned {code!r}, expected "
        "'ResourceNotFoundException'"
    )
    assert message == "The memory record was not found", (
        f"GetMemoryRecord on the deleted record: expected 'The memory record was not found', "
        f"got {message!r}"
    )
    mutate_code, mutate_message = _error(
        lambda: data.delete_memory_record(memoryId=memory_id, memoryRecordId=second_id)
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"a second DeleteMemoryRecord on the dead id {second_id!r} returned {mutate_code!r}, "
        "expected 'ResourceNotFoundException'"
    )
    assert mutate_message == "The memory record was not found", (
        f"second DeleteMemoryRecord on the dead id: expected 'The memory record was not found', "
        f"got {mutate_message!r}"
    )
    remaining = _poll_until(
        lambda: _listed_ids(data, memoryId=memory_id, namespace=namespace),
        lambda ids: ids == {original_id},
        timeout_s=30.0,
        interval_s=3.0,
        description=f"namespace {namespace} is back to the surviving record only",
    )
    assert remaining == {original_id}, (
        f"namespace {namespace!r} holds {sorted(remaining)!r} after deleting {second_id!r}, "
        f"expected exactly [{original_id!r}]"
    )

    # Terminal read: an independent GetMemoryRecord — a different operation from every mutation
    # above — on the surviving record at the destination.
    survivor = data.get_memory_record(
        memoryId=memory_id, memoryRecordId=original_id
    )["memoryRecord"]
    assert survivor["memoryRecordId"] == original_id, (
        f"GetMemoryRecord returned {survivor['memoryRecordId']!r}, expected {original_id!r}"
    )
    assert survivor["content"]["text"] == text, (
        f"the surviving record's content is {survivor['content']!r}, expected text {text!r}"
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


def _create_active_memory(ctx, control) -> str:
    name = "simparityidem" + ctx.unique_name("").replace("-", "")[:22]
    resp = control.create_memory(
        name=name,
        eventExpiryDuration=7,
        tags={"simparity": CHECK, "simparity-owner": "simparity-behavioral"},
    )
    memory = resp["memory"]
    memory_id = memory.get("id") or memory["arn"].rsplit("/", 1)[-1]
    ctx.on_cleanup(lambda: _ac_delete_memory(control, memory_id))

    status = _poll_until(
        lambda: control.get_memory(memoryId=memory_id)["memory"]["status"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED", "FAILED"),
        # 240s: a new memory can stay CREATING for more than 90s.
        timeout_s=240.0,
        interval_s=5.0,
        description=f"memory {memory_id} left CREATING",
    )
    assert status == "ACTIVE", (
        f"memory {memory_id} reached terminal status {status!r}, expected 'ACTIVE'"
    )
    return memory_id


def _batch_create_through_activation_gap(data, memory_id, records, token):
    """The batch write, or None while the memory reports ACTIVE but does not yet accept writes.

    Only the specific activation-gap refusal is absorbed; every other ClientError propagates, so
    a genuine validation or authorization failure is never turned into a timeout.
    """
    try:
        return data.batch_create_memory_records(
            memoryId=memory_id, records=records, clientToken=token
        )
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") == "ValidationException" and "not active" in str(
            err.get("Message", "")
        ):
            return None
        raise


def _listed_ids(data, **kwargs) -> set[str]:
    """Every memoryRecordId ListMemoryRecords reports for these scoping arguments.

    `memoryRecordSummaries` is REQUIRED in the output shape, so it is hard-subscripted rather
    than defaulted.
    """
    ids: set[str] = set()
    token = None
    for _ in range(20):
        params = dict(kwargs, maxResults=100)
        if token:
            params["nextToken"] = token
        resp = data.list_memory_records(**params)
        ids.update(s["memoryRecordId"] for s in resp["memoryRecordSummaries"])
        token = resp.get("nextToken")
        if not token:
            return ids
    raise AssertionError(
        f"ListMemoryRecords({kwargs!r}) did not stop paginating after 20 pages ({len(ids)} ids)"
    )


def _error(fn):
    """The AWS error (code, message), raising if the call unexpectedly SUCCEEDS — an
    over-permissive target's acceptance must not pass as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(
        f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """A bounded retry that RAISES on timeout and never returns its last observation."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: not observed within {timeout_s}s; last saw {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
