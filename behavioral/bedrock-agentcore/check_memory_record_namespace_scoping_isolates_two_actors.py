"""memory-record-namespace-scoping-isolates-two-actors."""
from __future__ import annotations

import datetime as _dt
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "memory-record-namespace-scoping-isolates-two-actors"
GROUP = "server-side"
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
    """Two records written into sibling namespaces of one memory in one BatchCreateMemoryRecords
    call do not see each other: ListMemoryRecords scoped to either namespace returns exactly that
    record, while the shared parent namespacePath returns both."""
    control = ctx.client("bedrock-agentcore-control")
    data = ctx.client("bedrock-agentcore")

    memory_id = _create_active_memory(ctx, control)

    # Sibling namespaces under one parent. Neither is a prefix of the other and neither equals
    # the other, so the isolation assertion holds whether `namespace` means exact-match or
    # prefix-match.
    tenant = ctx.unique_name("").replace("-", "")
    parent_ns = f"/simparity/{tenant}/actor/"
    ns_alpha = parent_ns + "alpha/facts/"
    ns_beta = parent_ns + "beta/facts/"
    text_alpha = f"alpha-secret-{tenant}"
    text_beta = f"beta-secret-{tenant}"

    now = _dt.datetime.now(_dt.timezone.utc)
    records = [
        {
            "requestIdentifier": "simparity-alpha",
            "namespaces": [ns_alpha],
            "content": {"text": text_alpha},
            "timestamp": now,
        },
        {
            "requestIdentifier": "simparity-beta",
            "namespaces": [ns_beta],
            "content": {"text": text_beta},
            "timestamp": now,
        },
    ]

    # ONE call, so the two namespaces are populated in the same instant: the twin control group
    # pattern. A target that stores everything in one undifferentiated bucket cannot pass
    # the two isolation legs below, and a target whose store is simply broken cannot pass the
    # two positive legs.
    created = _poll_until(
        lambda: _batch_create_through_activation_gap(data, memory_id, records),
        lambda r: r is not None,
        timeout_s=45.0,
        interval_s=5.0,
        description="BatchCreateMemoryRecords accepted by the freshly-created memory",
    )
    assert created["failedRecords"] == [], (
        "expected every record in the batch to succeed, but failedRecords was "
        f"{created['failedRecords']!r}"
    )
    by_request = {r["requestIdentifier"]: r for r in created["successfulRecords"]}
    assert set(by_request) == {"simparity-alpha", "simparity-beta"}, (
        "expected successfulRecords to echo both requestIdentifiers, got "
        f"{sorted(by_request)!r}"
    )
    for rid, rec in by_request.items():
        assert rec["status"] == "SUCCEEDED", (
            f"record {rid!r} reported status {rec['status']!r}, expected 'SUCCEEDED' "
            f"(errorCode={rec.get('errorCode')!r} errorMessage={rec.get('errorMessage')!r})"
        )
    id_alpha = by_request["simparity-alpha"]["memoryRecordId"]
    id_beta = by_request["simparity-beta"]["memoryRecordId"]
    assert id_alpha != id_beta, (
        f"both records came back with the same memoryRecordId {id_alpha!r}; two distinct records "
        "must get distinct ids"
    )
    for rid, mrid in (("alpha", id_alpha), ("beta", id_beta)):
        # Derived from the model's MemoryRecordId length trait, not from an observed value.
        assert 40 <= len(mrid) <= 50, (
            f"{rid} memoryRecordId {mrid!r} is {len(mrid)} chars; the modelled MemoryRecordId "
            "length constraint is 40..50"
        )

    # Positive leg 1: alpha's record really is listable under alpha's namespace.
    _poll_until(
        lambda: _listed_ids(data, memoryId=memory_id, namespace=ns_alpha),
        lambda ids: id_alpha in ids,
        timeout_s=20.0,
        interval_s=2.0,
        description=f"record {id_alpha} became listable under namespace {ns_alpha}",
    )
    # Positive leg 2: beta's record really is listable under beta's namespace. Both positives
    # land BEFORE either isolation assertion, so an absence below is absence-despite-presence,
    # not absence-because-nothing-was-stored.
    _poll_until(
        lambda: _listed_ids(data, memoryId=memory_id, namespace=ns_beta),
        lambda ids: id_beta in ids,
        timeout_s=20.0,
        interval_s=2.0,
        description=f"record {id_beta} became listable under namespace {ns_beta}",
    )

    # The discriminator, on fresh reads now that both records are demonstrably stored.
    alpha_scope = _listed_ids(data, memoryId=memory_id, namespace=ns_alpha)
    assert alpha_scope == {id_alpha}, (
        f"ListMemoryRecords(namespace={ns_alpha!r}) returned {sorted(alpha_scope)!r}; expected "
        f"exactly [{id_alpha!r}]. Beta's record {id_beta!r} living in a sibling namespace must "
        "not be visible here — a single shared bucket is the classic isolation bug"
    )
    beta_scope = _listed_ids(data, memoryId=memory_id, namespace=ns_beta)
    assert beta_scope == {id_beta}, (
        f"ListMemoryRecords(namespace={ns_beta!r}) returned {sorted(beta_scope)!r}; expected "
        f"exactly [{id_beta!r}], with alpha's record {id_alpha!r} scoped out"
    )

    # The shared parent, queried hierarchically, must return BOTH. This is the leg a target
    # that "isolates" by returning nothing at all cannot fake.
    path_scope = _poll_until(
        lambda: _listed_ids(data, memoryId=memory_id, namespacePath=parent_ns),
        lambda ids: {id_alpha, id_beta} <= ids,
        timeout_s=20.0,
        interval_s=2.0,
        description=f"namespacePath={parent_ns} surfaced both sibling records",
    )
    assert path_scope == {id_alpha, id_beta}, (
        f"ListMemoryRecords(namespacePath={parent_ns!r}) returned {sorted(path_scope)!r}; "
        f"expected exactly {sorted({id_alpha, id_beta})!r} — the hierarchical read must span "
        "both children and nothing else"
    )

    # The delete is already mandatory teardown for one record, so assert it: gone by an
    # independent read, a mutation on the dead id also refused, and the effect absent from the
    # list — while the twin survives, proving the delete was scoped and the store was not wiped.
    data.delete_memory_record(memoryId=memory_id, memoryRecordId=id_alpha)
    code, message = _error(
        lambda: data.get_memory_record(memoryId=memory_id, memoryRecordId=id_alpha)
    )
    assert code == "ResourceNotFoundException", (
        f"GetMemoryRecord on the deleted record {id_alpha!r} returned {code!r}, expected "
        "'ResourceNotFoundException'"
    )
    assert message == "The memory record was not found", (
        f"GetMemoryRecord on the deleted record: expected 'The memory record was not found', "
        f"got {message!r}"
    )
    mutate_code, mutate_message = _error(
        lambda: data.delete_memory_record(memoryId=memory_id, memoryRecordId=id_alpha)
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"a second DeleteMemoryRecord on the dead id {id_alpha!r} returned {mutate_code!r}, "
        "expected 'ResourceNotFoundException' — a delete that reports success on a gone record "
        "is over-permissive"
    )
    assert mutate_message == "The memory record was not found", (
        f"second DeleteMemoryRecord on the dead id: expected 'The memory record was not found', "
        f"got {mutate_message!r}"
    )
    emptied = _poll_until(
        lambda: _listed_ids(data, memoryId=memory_id, namespace=ns_alpha),
        lambda ids: not ids,
        timeout_s=20.0,
        interval_s=2.0,
        description=f"namespace {ns_alpha} became empty after its only record was deleted",
    )
    assert emptied == set(), (
        f"ListMemoryRecords(namespace={ns_alpha!r}) still returned {sorted(emptied)!r} after the "
        "record was deleted"
    )

    # Terminal read: an independent GetMemoryRecord (a different operation from every mutation
    # above) at the destination, on the surviving twin.
    survivor = data.get_memory_record(memoryId=memory_id, memoryRecordId=id_beta)["memoryRecord"]
    assert survivor["memoryRecordId"] == id_beta, (
        f"GetMemoryRecord returned id {survivor['memoryRecordId']!r}, expected {id_beta!r}"
    )
    assert survivor["content"]["text"] == text_beta, (
        f"the surviving record's content is {survivor['content']!r}, expected text {text_beta!r}"
    )
    assert ns_beta in survivor["namespaces"], (
        f"the surviving record reports namespaces {survivor['namespaces']!r}, which does not "
        f"contain the namespace it was written to, {ns_beta!r}"
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
    """Create-or-adopt is not available here (CreateMemory has no idempotent get-by-name), so
    create a uniquely named memory, tag it, register
    its teardown, and wait for ACTIVE with a bounded poll that RAISES on timeout."""
    name = "simparityns" + ctx.unique_name("").replace("-", "")[:24]
    resp = control.create_memory(
        name=name,
        eventExpiryDuration=7,
        tags={"simparity": CHECK, "simparity-owner": "simparity-behavioral"},
    )
    memory = resp["memory"]
    memory_id = memory.get("id") or memory["arn"].rsplit("/", 1)[-1]
    ctx.on_cleanup(lambda: _ac_delete_memory(control, memory_id))

    def _status() -> str:
        return control.get_memory(memoryId=memory_id)["memory"]["status"]

    status = _poll_until(
        _status,
        lambda s: s in ("ACTIVE", "CREATE_FAILED", "FAILED"),
        # 240s: a new memory with a strategy can stay CREATING for well over 90s.
        timeout_s=240.0,
        interval_s=5.0,
        description=f"memory {memory_id} left CREATING",
    )
    assert status == "ACTIVE", (
        f"memory {memory_id} reached terminal status {status!r}, expected 'ACTIVE'"
    )
    return memory_id


def _batch_create_through_activation_gap(data, memory_id, records):
    """The batch write, or None while the memory is reported ACTIVE but not yet accepting writes.

    Only the specific activation-gap refusal is absorbed; every other ClientError
    propagates, so a genuine validation or authorization failure never becomes a timeout.
    """
    try:
        return data.batch_create_memory_records(memoryId=memory_id, records=records)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") == "ValidationException" and "not active" in str(
            err.get("Message", "")
        ):
            return None
        raise


def _listed_ids(data, **kwargs) -> set[str]:
    """The full set of memoryRecordIds ListMemoryRecords reports for these scoping arguments.

    `memoryRecordSummaries` is a REQUIRED member of the output shape, so it is hard-subscripted:
    a target that omits it must fail loudly rather than be handed an empty default.
    """
    ids: set[str] = set()
    token = None
    for _ in range(20):
        params = dict(kwargs, maxResults=100)
        if token:
            params["nextToken"] = token
        resp = data.list_memory_records(**params)
        ids.update(summary["memoryRecordId"] for summary in resp["memoryRecordSummaries"])
        token = resp.get("nextToken")
        if not token:
            return ids
    raise AssertionError(
        f"ListMemoryRecords({kwargs!r}) did not stop paginating after 20 pages; "
        f"saw {len(ids)} ids"
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
