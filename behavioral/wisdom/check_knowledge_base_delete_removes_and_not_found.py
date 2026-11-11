"""knowledge-base-delete-removes-and-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "knowledge-base-delete-removes-and-not-found"
GROUP = "state"
SERVICES = ["wisdom"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteKnowledgeBase removes the knowledge base; a subsequent GetKnowledgeBase returns
    ResourceNotFoundException, and the dead id also rejects a second DeleteKnowledgeBase rather than
    silently no-op'ing or resurrecting anything."""
    wisdom = ctx.client("wisdom")
    kb = wisdom.create_knowledge_base(
        name=ctx.unique_name("sim2real-kb-"),
        knowledgeBaseType="CUSTOM",
        tags={"team": "support", "stage": "sim2real-behav"},
    )["knowledgeBase"]
    kb_id = kb["knowledgeBaseId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb_id)))

    _poll_until(
        lambda: wisdom.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"],
        lambda k: k["status"] == "ACTIVE",
        timeout_s=60.0,
    )

    wisdom.delete_knowledge_base(knowledgeBaseId=kb_id)
    _poll_not_found(lambda: wisdom.get_knowledge_base(knowledgeBaseId=kb_id), timeout_s=60.0)

    code, message = _error(lambda: wisdom.get_knowledge_base(knowledgeBaseId=kb_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == "Knowledge Base does not exist.", f"expected the knowledge-base not-found message, got {message!r}"

    second_delete_code, second_delete_message = _error(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb_id))
    assert second_delete_code == "ResourceNotFoundException", (
        f"expected a second DeleteKnowledgeBase on the dead id to reject with "
        f"ResourceNotFoundException, got {second_delete_code!r}"
    )
    assert second_delete_message == "Knowledge Base does not exist.", (
        f"expected the knowledge-base not-found message on re-delete, got {second_delete_message!r}"
    )


def _safe_delete(fn):
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
