"""quick-response-create-get-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "quick-response-create-get-lifecycle"
GROUP = "lifecycle"
SERVICES = ["qconnect"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateQuickResponse reaches CREATED, GetQuickResponse echoes the exact content provided,
    and once deleted the quick response is gone and its id can no longer be mutated."""
    qc = ctx.client("qconnect")
    kb_id = _create_active_knowledge_base(ctx, qc, "QUICK_RESPONSES")

    name = ctx.unique_name("sim2real-qc-qr-")
    text = "Thanks for calling, how can I help you today?"
    qr = qc.create_quick_response(
        knowledgeBaseId=kb_id, name=name, content={"content": text}, tags={"sim2real": CHECK}
    )["quickResponse"]
    qr_id = qr["quickResponseId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: qc.delete_quick_response(knowledgeBaseId=kb_id, quickResponseId=qr_id))
    )

    status = _poll_until(
        lambda: qc.get_quick_response(knowledgeBaseId=kb_id, quickResponseId=qr_id)["quickResponse"]["status"],
        lambda s: s in ("CREATED", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert status == "CREATED", f"quick response did not reach CREATED, got {status}"

    final = qc.get_quick_response(knowledgeBaseId=kb_id, quickResponseId=qr_id)["quickResponse"]
    assert final["name"] == name, f"expected name {name!r}, got {final['name']!r}"
    assert final["contents"]["plainText"]["content"] == text, (
        f"expected content {text!r}, got {final['contents']['plainText']['content']!r}"
    )

    qc.delete_quick_response(knowledgeBaseId=kb_id, quickResponseId=qr_id)
    read_code, read_message = _client_error(lambda: qc.get_quick_response(knowledgeBaseId=kb_id, quickResponseId=qr_id))
    assert read_code == "ResourceNotFoundException", (
        f"expected deleted quick response to read back not-found, got {read_code}"
    )
    assert read_message == "QuickResponse does not exist.", f"unexpected message {read_message!r}"
    delete_code, delete_message = _client_error(lambda: qc.delete_quick_response(knowledgeBaseId=kb_id, quickResponseId=qr_id))
    assert delete_code == "ResourceNotFoundException", (
        f"expected second delete on the same id to be not-found, got {delete_code}"
    )
    assert delete_message == "QuickResponse does not exist.", f"unexpected message {delete_message!r}"


def _create_active_knowledge_base(ctx, qc, kb_type: str) -> str:
    name = ctx.unique_name("sim2real-qc-kb-")
    kb_id = qc.create_knowledge_base(name=name, knowledgeBaseType=kb_type, tags={"sim2real": CHECK})[
        "knowledgeBase"
    ]["knowledgeBaseId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: qc.delete_knowledge_base(knowledgeBaseId=kb_id)))
    status = _poll_until(
        lambda: qc.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]["status"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert status == "ACTIVE", f"knowledge base did not reach ACTIVE, got {status}"
    return kb_id


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _client_error(fn):
    """Call fn(); return the (code, message) it is refused with. An unexpected success raises,
    so a target that accepts what AWS refuses reads as an acceptance, not a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    if not predicate(value):
        raise TimeoutError(f"poll timed out after {timeout_s}s, last value: {value!r}")
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
