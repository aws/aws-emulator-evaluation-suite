"""quick-response-channels-language-fields-persisted."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "quick-response-channels-language-fields-persisted"
GROUP = "lifecycle"
SERVICES = ["wisdom"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateQuickResponse persists channels, language and description alongside the shortcut
    key and content, and GetQuickResponse reflects every one of them exactly."""
    wisdom = ctx.client("wisdom")
    kb = wisdom.create_knowledge_base(
        name=ctx.unique_name("sim2real-behav-kb-"),
        knowledgeBaseType="QUICK_RESPONSES",
        tags={"sim2real-behav": "true"},
    )["knowledgeBase"]
    kb_id = kb["knowledgeBaseId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb_id)))
    _poll_until(
        lambda: wisdom.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"],
        lambda k: k["status"] == "ACTIVE",
        timeout_s=60.0,
    )

    qr_name = ctx.unique_name("sim2real-behav-qr-")[:40]
    created = wisdom.create_quick_response(
        knowledgeBaseId=kb_id,
        name=qr_name,
        content={"content": "Merci pour votre patience."},
        shortcutKey="fields1",
        description="French courtesy response",
        channels=["Chat"],
        language="fr_FR",
        tags={"sim2real-behav": "true"},
    )["quickResponse"]
    qr_id = created["quickResponseId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_quick_response(knowledgeBaseId=kb_id, quickResponseId=qr_id)))

    final = _poll_until(
        lambda: wisdom.get_quick_response(knowledgeBaseId=kb_id, quickResponseId=qr_id)["quickResponse"],
        lambda q: q["status"] in ("CREATED", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert final["status"] == "CREATED", f"expected status CREATED, got {final['status']!r}"
    assert final["description"] == "French courtesy response", (
        f"expected description 'French courtesy response', got {final['description']!r}"
    )
    assert final["channels"] == ["Chat"], f"expected channels ['Chat'], got {final['channels']!r}"
    assert final["language"] == "fr_FR", f"expected language 'fr_FR', got {final['language']!r}"
    assert final["shortcutKey"] == "fields1", f"expected shortcutKey 'fields1', got {final['shortcutKey']!r}"
    assert final["contents"]["plainText"]["content"] == "Merci pour votre patience.", (
        f"expected content 'Merci pour votre patience.', got {final['contents']!r}"
    )


def _safe_delete(fn):
    from botocore.exceptions import ClientError

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
