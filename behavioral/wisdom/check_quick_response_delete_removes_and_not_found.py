"""quick-response-delete-removes-and-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "quick-response-delete-removes-and-not-found"
GROUP = "state"
SERVICES = ["wisdom"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteQuickResponse removes it; a subsequent GetQuickResponse returns ResourceNotFoundException,
    and an UpdateQuickResponse on the same dead id is rejected the same way."""
    wisdom = ctx.client("wisdom")
    kb = wisdom.create_knowledge_base(
        name=ctx.unique_name("sim2real-kb-"), knowledgeBaseType="QUICK_RESPONSES"
    )["knowledgeBase"]
    kb_id = kb["knowledgeBaseId"]
    ctx.on_cleanup(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb_id))

    qr = wisdom.create_quick_response(
        knowledgeBaseId=kb_id, name=ctx.unique_name("sim2real-qr-")[:40], content={"content": "hello"}
    )["quickResponse"]
    qr_id = qr["quickResponseId"]

    _poll_until(
        lambda: wisdom.get_quick_response(knowledgeBaseId=kb_id, quickResponseId=qr_id)["quickResponse"],
        lambda q: q["status"] == "CREATED",
        timeout_s=60.0,
    )

    wisdom.delete_quick_response(knowledgeBaseId=kb_id, quickResponseId=qr_id)
    _poll_not_found(
        lambda: wisdom.get_quick_response(knowledgeBaseId=kb_id, quickResponseId=qr_id), timeout_s=60.0
    )

    code, message = _error(
        lambda: wisdom.get_quick_response(knowledgeBaseId=kb_id, quickResponseId=qr_id)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException from Get, got {code!r}"
    assert message == "QuickResponse does not exist.", f"expected the quick-response not-found message, got {message!r}"

    update_code, update_message = _error(
        lambda: wisdom.update_quick_response(
            knowledgeBaseId=kb_id, quickResponseId=qr_id, isActive=True
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected UpdateQuickResponse on the deleted id to also be rejected, got {update_code!r}"
    )
    assert update_message == "QuickResponse does not exist.", (
        f"expected the quick-response not-found message from Update, got {update_message!r}"
    )


def _error(fn):
    """Return the (code, message) of the ClientError fn() raises; a success fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _poll_not_found(get_fn, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            get_fn()
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError("resource was not removed within timeout")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
