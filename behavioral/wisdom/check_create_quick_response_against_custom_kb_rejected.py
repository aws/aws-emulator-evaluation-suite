"""create-quick-response-against-custom-kb-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-quick-response-against-custom-kb-rejected"
GROUP = "overly-permissive"
SERVICES = ["wisdom"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateQuickResponse and ListQuickResponses on a CUSTOM knowledge base fail with ValidationException
    and the exact not-supported message; on a QUICK_RESPONSES knowledge base the quick response settles
    CREATED and is the one listed.
    """
    wisdom = ctx.client("wisdom")
    kb_custom = wisdom.create_knowledge_base(
        name=ctx.unique_name("sim2real-kbcustom-"),
        knowledgeBaseType="CUSTOM",
        tags={"team": "support", "stage": "sim2real-behav"},
    )["knowledgeBase"]
    kb_custom_id = kb_custom["knowledgeBaseId"]
    ctx.on_cleanup(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb_custom_id))

    name = ctx.unique_name("sim2real-qr-")[:40]
    code, message = _error(
        lambda: wisdom.create_quick_response(
            knowledgeBaseId=kb_custom_id, name=name, content={"content": "nope"}
        )
    )
    assert code == "ValidationException", (
        f"expected CreateQuickResponse against a CUSTOM knowledge base to be rejected with "
        f"ValidationException, got {code!r}"
    )
    assert message == "QuickResponse APIs are not supported for CUSTOM knowledge bases", (
        f"expected the CUSTOM-knowledge-base refusal message, got {message!r}"
    )

    # effect absent, by consequence: the QuickResponse read surface itself is rejected for a
    # CUSTOM knowledge base, so there is no independent read that could ever show the refused
    # create having taken effect there
    list_code, list_message = _error(lambda: wisdom.list_quick_responses(knowledgeBaseId=kb_custom_id))
    assert list_code == "ValidationException", (
        f"expected ListQuickResponses against a CUSTOM knowledge base to also be rejected with "
        f"ValidationException, got {list_code!r}"
    )
    assert list_message == "QuickResponse APIs are not supported for CUSTOM knowledge bases", (
        f"expected the CUSTOM-knowledge-base refusal message from ListQuickResponses, got {list_message!r}"
    )

    # positive control: the identical flow against a QUICK_RESPONSES knowledge base succeeds
    kb_qr = wisdom.create_knowledge_base(
        name=ctx.unique_name("sim2real-kbqr-"),
        knowledgeBaseType="QUICK_RESPONSES",
        tags={"team": "support", "stage": "sim2real-behav"},
    )["knowledgeBase"]
    kb_qr_id = kb_qr["knowledgeBaseId"]
    ctx.on_cleanup(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb_qr_id))

    qr = wisdom.create_quick_response(
        knowledgeBaseId=kb_qr_id,
        name=name,
        content={"content": "yep"},
        tags={"team": "support", "stage": "sim2real-behav"},
    )["quickResponse"]
    qr_id = qr["quickResponseId"]
    ctx.on_cleanup(lambda: wisdom.delete_quick_response(knowledgeBaseId=kb_qr_id, quickResponseId=qr_id))

    # terminal read is independent of the create call that produced qr
    settled = _poll_until(
        lambda: wisdom.get_quick_response(knowledgeBaseId=kb_qr_id, quickResponseId=qr_id)["quickResponse"],
        lambda q: q["status"] in ("CREATED", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert settled["status"] == "CREATED", (
        f"the positive-control quick response did not settle CREATED, it settled "
        f"{settled['status']!r}"
    )
    listed_qr = wisdom.list_quick_responses(knowledgeBaseId=kb_qr_id)["quickResponseSummaries"]
    listed_qr_ids = {q["quickResponseId"] for q in listed_qr}
    assert listed_qr_ids == {qr_id}, (
        f"expected exactly the positive-control quick response to be listed, got {listed_qr_ids!r}"
    )


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
