"""quick-response-duplicate-name-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "quick-response-duplicate-name-rejected"
GROUP = "state"
SERVICES = ["qconnect"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateQuickResponse with a name that collides in the same knowledge base is rejected."""
    qc = ctx.client("qconnect")
    kb_id = _create_active_knowledge_base(ctx, qc, "QUICK_RESPONSES")

    name = ctx.unique_name("sim2real-qc-qr-dup-")
    first_id = qc.create_quick_response(
        knowledgeBaseId=kb_id,
        name=name,
        content={"content": "First version"},
        tags={"Environment": "sim2real-test"},
    )["quickResponse"]["quickResponseId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: qc.delete_quick_response(knowledgeBaseId=kb_id, quickResponseId=first_id))
    )
    first_status = _poll_until(
        lambda: qc.get_quick_response(knowledgeBaseId=kb_id, quickResponseId=first_id)["quickResponse"]["status"],
        lambda s: s in ("CREATED", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert first_status == "CREATED", f"positive control quick response did not reach CREATED, got {first_status}"

    code, message = _client_error(
        lambda: qc.create_quick_response(knowledgeBaseId=kb_id, name=name, content={"content": "Second version"})
    )
    assert code == "ConflictException", f"expected ConflictException for duplicate name, got {code}"
    assert message == "The value for name is already in use. Please update and try again.", (
        f"unexpected message {message!r}"
    )

    listed = qc.list_quick_responses(knowledgeBaseId=kb_id)["quickResponseSummaries"]
    matching = [q for q in listed if q["name"] == name]
    assert len(matching) == 1, f"expected exactly one quick response named {name!r}, found {len(matching)}"

    other_name = ctx.unique_name("sim2real-qc-qr-dup-other-")
    second_id = qc.create_quick_response(
        knowledgeBaseId=kb_id,
        name=other_name,
        content={"content": "Different name works fine"},
        tags={"Environment": "sim2real-test"},
    )["quickResponse"]["quickResponseId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: qc.delete_quick_response(knowledgeBaseId=kb_id, quickResponseId=second_id)
        )
    )
    assert second_id != first_id, f"expected a distinct quickResponseId for the non-colliding name, got {second_id!r} twice"


def _create_active_knowledge_base(ctx, qc, kb_type: str) -> str:
    name = ctx.unique_name("sim2real-qc-kb-")
    kb_id = qc.create_knowledge_base(
        name=name, knowledgeBaseType=kb_type, tags={"Environment": "sim2real-test"}
    )["knowledgeBase"]["knowledgeBaseId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: qc.delete_knowledge_base(knowledgeBaseId=kb_id)))
    status = _poll_until(
        lambda: qc.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]["status"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert status == "ACTIVE", f"prerequisite knowledge base did not reach ACTIVE, got {status}"
    return kb_id


def _client_error(fn):
    """Call fn(); return the (code, message) it is refused with. An unexpected success raises,
    so a target that accepts what AWS refuses reads as an acceptance, not a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
