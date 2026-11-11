"""quick-response-shortcut-key-conflict-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "quick-response-shortcut-key-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["wisdom"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateQuickResponse in the same knowledge base reusing an already-taken
    shortcutKey must be rejected with ConflictException, must not create a second quick response,
    and a different shortcutKey (positive control) must succeed."""
    wisdom = ctx.client("wisdom")
    kb = wisdom.create_knowledge_base(
        name=ctx.unique_name("sim2real-behav-kb-"),
        knowledgeBaseType="QUICK_RESPONSES",
        tags={"team": "support", "stage": "sim2real-behav"},
    )["knowledgeBase"]
    kb_id = kb["knowledgeBaseId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb_id)))
    _poll_until(
        lambda: wisdom.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"],
        lambda k: k["status"] == "ACTIVE",
        timeout_s=60.0,
    )

    shared_key = "dupkey1"
    qr1 = wisdom.create_quick_response(
        knowledgeBaseId=kb_id,
        name=ctx.unique_name("sim2real-behav-qr1-"),
        content={"content": "First response"},
        shortcutKey=shared_key,
        tags={"team": "support", "stage": "sim2real-behav"},
    )["quickResponse"]
    qr1_id = qr1["quickResponseId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_quick_response(knowledgeBaseId=kb_id, quickResponseId=qr1_id)))
    qr1_settled = _poll_until(
        lambda: wisdom.get_quick_response(knowledgeBaseId=kb_id, quickResponseId=qr1_id)["quickResponse"],
        lambda q: q["status"] in ("CREATED", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert qr1_settled["status"] == "CREATED", (
        f"the first quick response did not settle CREATED, it settled {qr1_settled['status']!r} — "
        f"the conflict this check exercises never gets a chance to occur"
    )

    # break exactly one thing: reuse the shortcutKey on a new quick response
    code, message = _error(
        lambda: wisdom.create_quick_response(
            knowledgeBaseId=kb_id,
            name=ctx.unique_name("sim2real-behav-qr2-"),
            content={"content": "Second response"},
            shortcutKey=shared_key,
        )
    )
    assert code == "ConflictException", (
        f"reusing an already-taken shortcutKey should be refused with ConflictException, got {code!r}"
    )
    assert message == "The value for shortcut key is already in use. Please update and try again.", (
        f"expected the shortcut-key-in-use message, got {message!r}"
    )

    # effect absent: only the first quick response exists in this knowledge base
    listed = wisdom.list_quick_responses(knowledgeBaseId=kb_id)["quickResponseSummaries"]
    assert len(listed) == 1, f"expected exactly one quick response after the refused conflict, got {listed!r}"
    assert listed[0]["quickResponseId"] == qr1_id, (
        f"the surviving quick response is {listed[0]['quickResponseId']!r}, not the original {qr1_id!r}"
    )

    # positive control: a different shortcutKey succeeds — proves CreateQuickResponse still works
    # in this knowledge base and the refusal above is specific to the shortcutKey collision, not a
    # blanket denial
    qr3 = wisdom.create_quick_response(
        knowledgeBaseId=kb_id,
        name=ctx.unique_name("sim2real-behav-qr3-"),
        content={"content": "Third response"},
        shortcutKey="okkey2",
        tags={"team": "support", "stage": "sim2real-behav"},
    )["quickResponse"]
    qr3_id = qr3["quickResponseId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_quick_response(knowledgeBaseId=kb_id, quickResponseId=qr3_id)))

    # terminal read is independent of the create call that produced qr3
    qr3_settled = _poll_until(
        lambda: wisdom.get_quick_response(knowledgeBaseId=kb_id, quickResponseId=qr3_id)["quickResponse"],
        lambda q: q["status"] in ("CREATED", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert qr3_settled["status"] == "CREATED", (
        f"the positive-control quick response did not settle CREATED, it settled "
        f"{qr3_settled['status']!r}"
    )
    assert qr3_settled["shortcutKey"] == "okkey2", (
        f"the positive-control quick response's shortcutKey read back as "
        f"{qr3_settled['shortcutKey']!r}, not 'okkey2'"
    )
    listed_after = wisdom.list_quick_responses(knowledgeBaseId=kb_id)["quickResponseSummaries"]
    listed_ids = {q["quickResponseId"] for q in listed_after}
    assert listed_ids == {qr1_id, qr3_id}, (
        f"expected exactly the original and positive-control quick responses to be listed, got {listed_ids!r}"
    )


def _safe_delete(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Return the (code, message) of the ClientError fn() raises; a success fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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
