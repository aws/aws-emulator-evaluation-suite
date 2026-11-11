"""create-quick-response-invalid-content-type-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-quick-response-invalid-content-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["wisdom"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateQuickResponse with a contentType outside the quick-response pattern fails with
    ValidationException and the exact pattern message and lists nothing; a plain-format contentType is
    created and read back unchanged.
    """
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

    # break exactly one thing: an unsupported contentType value
    code, message = _error(
        lambda: wisdom.create_quick_response(
            knowledgeBaseId=kb_id,
            name=ctx.unique_name("sim2real-behav-qr-")[:40],
            content={"content": "irrelevant"},
            contentType="application/json",
        )
    )
    assert code == "ValidationException", f"expected ValidationException for an unsupported contentType, got {code!r}"
    assert message == (
        "1 validation error detected: Value 'application/json' at 'contentType' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: "
        "(application/x\\.quickresponse;format=(plain|markdown))"
    ), f"expected the contentType pattern-violation message, got {message!r}"

    # effect absent: nothing was created in this knowledge base
    listed = wisdom.list_quick_responses(knowledgeBaseId=kb_id)["quickResponseSummaries"]
    assert listed == [], f"expected no quick responses after the rejected create, got {listed!r}"

    # positive control: a valid contentType succeeds
    good = wisdom.create_quick_response(
        knowledgeBaseId=kb_id,
        name=ctx.unique_name("sim2real-behav-qr-")[:40],
        content={"content": "irrelevant"},
        contentType="application/x.quickresponse;format=plain",
        tags={"team": "support", "stage": "sim2real-behav"},
    )["quickResponse"]
    ctx.on_cleanup(
        lambda: _safe_delete(
            lambda: wisdom.delete_quick_response(knowledgeBaseId=kb_id, quickResponseId=good["quickResponseId"])
        )
    )
    assert good["contentType"] == "application/x.quickresponse;format=plain", (
        f"expected create response contentType 'application/x.quickresponse;format=plain', got {good['contentType']!r}"
    )

    # terminal assertion: an independent read at the destination confirms it persisted
    fetched = wisdom.get_quick_response(knowledgeBaseId=kb_id, quickResponseId=good["quickResponseId"])["quickResponse"]
    assert fetched["contentType"] == "application/x.quickresponse;format=plain", (
        f"expected persisted contentType 'application/x.quickresponse;format=plain', got {fetched['contentType']!r}"
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
