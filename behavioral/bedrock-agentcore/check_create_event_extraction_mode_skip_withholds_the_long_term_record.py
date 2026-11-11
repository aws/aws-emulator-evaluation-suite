"""create-event-extraction-mode-skip-withholds-the-long-term-record."""
from __future__ import annotations

import datetime as _dt
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-event-extraction-mode-skip-withholds-the-long-term-record"
GROUP = "server-side"
SERVICES = ["bedrock-agentcore"]

_BEDROCK_MANAGED_POLICY = "arn:aws:iam::aws:policy/AmazonBedrockFullAccess"


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Long-term extraction honours extractionMode: a conversational event written WITHOUT
    extractionMode converges to a derived memory record in its strategy namespace, while an event
    written just before it with extractionMode=SKIP never does yet stays readable short-term."""
    iam = ctx.client("iam")
    control = ctx.client("bedrock-agentcore-control")
    data = ctx.client("bedrock-agentcore")

    role_arn = _create_memory_execution_role(ctx, iam)
    actor_id = ctx.unique_name("simparityactor").replace("-", "")
    session_extract = ctx.unique_name("simparitykeep").replace("-", "")
    session_skip = ctx.unique_name("simparityskip").replace("-", "")
    template = "/simparity/{actorId}/{sessionId}/"
    memory_id = _create_active_memory_with_strategy(ctx, control, role_arn, template)

    ns_extract = f"/simparity/{actor_id}/{session_extract}/"
    ns_skip = f"/simparity/{actor_id}/{session_skip}/"

    fact_extract = f"The build passphrase for release {session_extract} is quetzal-alpha."
    fact_skip = f"The build passphrase for release {session_skip} is quetzal-bravo."

    # Two events differing in EXACTLY one thing: extractionMode. The extracting event is written
    # AFTER the SKIP event, so once it has converged the SKIP event would have been extracted too:
    # it is the positive control that makes the SKIP session's emptiness evidence.
    started = time.monotonic()
    _create_conversational_event(
        data, memory_id, actor_id, session_skip, fact_skip, extraction_mode="SKIP"
    )
    _create_conversational_event(data, memory_id, actor_id, session_extract, fact_extract)

    extracted = _poll_until(
        lambda: _listed_ids(data, memoryId=memory_id, namespace=ns_extract),
        lambda ids: bool(ids),
        timeout_s=240.0,
        interval_s=2.0,
        description=(
            f"long-term extraction produced a record under {ns_extract} for the event written "
            "without extractionMode"
        ),
    )
    latency_s = time.monotonic() - started

    # The derived record must actually reflect the ingested fact, and it must name the strategy
    # that produced it (MemoryRecordSummary.memoryStrategyId is a REQUIRED member).
    summaries = _summaries(data, memoryId=memory_id, namespace=ns_extract)
    assert summaries, (
        f"namespace {ns_extract} reported ids {sorted(extracted)!r} but no summaries"
    )
    # default=str because summaries carry boto3-parsed datetimes, which json.dumps refuses
    # ("Object of type datetime is not JSON serializable"). Safe here and only here: this blob is
    # substring-searched for the marker below and quoted in the failure message -- it is never
    # compared byte-for-byte, so stringifying timestamps cannot mask a difference that matters.
    blob = json.dumps(summaries, default=str)
    assert session_extract in blob, (
        "the derived record's content does not mention the distinctive marker "
        f"{session_extract!r} that was only ever supplied to CreateEvent: {blob[:400]!r}"
    )
    for summary in summaries:
        assert summary["memoryStrategyId"], (
            f"derived record {summary['memoryRecordId']!r} reports an empty memoryStrategyId; "
            "an extracted record must name the strategy that produced it"
        )

    # Absence for the SKIP session after the later event converged, held for >= 3x the measured
    # positive latency and asserted on TWO independent observables.
    window_s = min(max(3.0 * latency_s, 30.0), 180.0)
    deadline = time.monotonic() + window_s
    while True:
        skipped_ids = _listed_ids(data, memoryId=memory_id, namespace=ns_skip)
        assert skipped_ids == set(), (
            f"ListMemoryRecords(namespace={ns_skip!r}) returned {sorted(skipped_ids)!r}; the "
            "event for that session set extractionMode=SKIP and must never be extracted into "
            "long-term memory"
        )
        if time.monotonic() >= deadline:
            break
        time.sleep(2.0)
    retrieved = data.retrieve_memory_records(
        memoryId=memory_id,
        namespace=ns_skip,
        searchCriteria={"searchQuery": fact_skip, "topK": 5},
    )["memoryRecordSummaries"]
    assert retrieved == [], (
        "the second observable disagrees: RetrieveMemoryRecords searching the SKIP session's "
        f"namespace {ns_skip!r} for its own text returned {retrieved!r}, expected [] after the "
        f"later event without extractionMode was already extracted; held {window_s:.0f}s"
    )

    # The SKIP event IS stored short-term. An independent read through a different
    # operation, at the destination, separates "excluded from extraction" from "never stored".
    events = data.list_events(
        memoryId=memory_id, actorId=actor_id, sessionId=session_skip, maxResults=100,
        includePayloads=True,
    )["events"]
    assert len(events) == 1, (
        f"ListEvents for the SKIP session returned {len(events)} events, expected exactly 1: "
        f"{[e.get('eventId') for e in events]!r}"
    )
    payload_blob = json.dumps(events[0]["payload"], default=str)
    assert fact_skip in payload_blob, (
        "the SKIP event's short-term payload does not contain the text it was created with; "
        f"extractionMode=SKIP must not discard the event: {payload_blob[:300]!r}"
    )

    # Repair the one withheld thing on the SAME wiring: a second event in the SAME session with
    # extractionMode omitted must now converge into the namespace that stayed empty. A target
    # with no extraction path at all fails here; a target that extracts regardless failed above.
    _create_conversational_event(
        data,
        memory_id,
        actor_id,
        session_skip,
        f"Correction: the build passphrase for release {session_skip} is quetzal-charlie.",
    )
    repaired = _poll_until(
        lambda: _listed_ids(data, memoryId=memory_id, namespace=ns_skip),
        lambda ids: bool(ids),
        timeout_s=240.0,
        interval_s=2.0,
        description=(
            f"removing extractionMode let namespace {ns_skip} receive a derived record, proving "
            "the earlier emptiness was the SKIP flag and not a missing pipeline"
        ),
    )
    assert repaired, f"namespace {ns_skip} is still empty after the repair event"

    # Terminal read: GetMemoryRecord — a different operation from CreateEvent and from every
    # List/Retrieve above — on one of the newly derived records at the destination.
    record_id = sorted(repaired)[0]
    got = data.get_memory_record(memoryId=memory_id, memoryRecordId=record_id)["memoryRecord"]
    assert got["memoryRecordId"] == record_id, (
        f"GetMemoryRecord returned id {got['memoryRecordId']!r}, expected {record_id!r}"
    )
    assert ns_skip in got["namespaces"], (
        f"the derived record reports namespaces {got['namespaces']!r}, which does not contain "
        f"the resolved strategy namespace {ns_skip!r} it was listed under"
    )


# ===== helpers =====


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


def _create_memory_execution_role(ctx, iam) -> str:
    role_name = ctx.unique_name("simparity-agentcore-mem-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    created = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "simparity", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_BEDROCK_MANAGED_POLICY)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_BEDROCK_MANAGED_POLICY)
    )
    return created["Role"]["Arn"]


def _create_active_memory_with_strategy(ctx, control, role_arn, template) -> str:
    """Create a memory whose semantic strategy writes into `template`, and wait for ACTIVE.

    The IAM role has to propagate before AgentCore can assume it, so CreateMemory is retried
    through the specific propagation refusals with a bounded deadline that RAISES.
    """
    name = "simparityskip" + ctx.unique_name("").replace("-", "")[:24]

    def _attempt():
        try:
            return control.create_memory(
                name=name,
                eventExpiryDuration=7,
                memoryExecutionRoleArn=role_arn,
                memoryStrategies=[
                    {
                        "semanticMemoryStrategy": {
                            "name": "simparity_semantic",
                            "namespaces": [template],
                        }
                    }
                ],
                tags={"simparity": CHECK, "simparity-owner": "simparity-behavioral"},
            )
        except ClientError as exc:
            err = exc.response.get("Error", {})
            message = str(err.get("Message", ""))
            propagating = err.get("Code") in ("ValidationException", "AccessDeniedException") and (
                "assume" in message.lower() or "role" in message.lower()
            )
            if propagating:
                return None
            raise

    resp = _poll_until(
        _attempt,
        lambda r: r is not None,
        timeout_s=60.0,
        interval_s=5.0,
        description="CreateMemory accepted the freshly created execution role",
    )
    memory = resp["memory"]
    memory_id = memory.get("id") or memory["arn"].rsplit("/", 1)[-1]
    ctx.on_cleanup(lambda: _ac_delete_memory(control, memory_id))

    status = _poll_until(
        lambda: control.get_memory(memoryId=memory_id)["memory"]["status"],
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


def _create_conversational_event(
    data, memory_id, actor_id, session_id, text, *, extraction_mode=None
):
    params = {
        "memoryId": memory_id,
        "actorId": actor_id,
        "sessionId": session_id,
        "eventTimestamp": _dt.datetime.now(_dt.timezone.utc),
        "payload": [{"conversational": {"content": {"text": text}, "role": "USER"}}],
    }
    if extraction_mode is not None:
        params["extractionMode"] = extraction_mode
    return data.create_event(**params)["event"]


def _summaries(data, **kwargs) -> list[dict]:
    """Every MemoryRecordSummary ListMemoryRecords reports for these scoping arguments.

    `memoryRecordSummaries` is REQUIRED in the output shape, so it is hard-subscripted.
    """
    out: list[dict] = []
    token = None
    for _ in range(20):
        params = dict(kwargs, maxResults=100)
        if token:
            params["nextToken"] = token
        resp = data.list_memory_records(**params)
        out.extend(resp["memoryRecordSummaries"])
        token = resp.get("nextToken")
        if not token:
            return out
    raise AssertionError(
        f"ListMemoryRecords({kwargs!r}) did not stop paginating after 20 pages ({len(out)} rows)"
    )


def _listed_ids(data, **kwargs) -> set[str]:
    return {s["memoryRecordId"] for s in _summaries(data, **kwargs)}


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
