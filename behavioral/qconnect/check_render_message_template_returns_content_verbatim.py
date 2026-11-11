"""render-message-template-returns-content-verbatim."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "render-message-template-returns-content-verbatim"
GROUP = "data-plane"
SERVICES = ["qconnect"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """RenderMessageTemplate returns the exact static body content with no unresolved placeholders."""
    qc = ctx.client("qconnect")
    kb_id = _create_active_knowledge_base(ctx, qc, "MESSAGE_TEMPLATES")

    body_text = "Thank you for contacting support. Your case has been received."
    name = ctx.unique_name("sim2real-qc-tmpl-")
    template_id = qc.create_message_template(
        knowledgeBaseId=kb_id,
        name=name,
        channelSubtype="SMS",
        content={"sms": {"body": {"plainText": {"content": body_text}}}},
        tags={"sim2real-owner": "behavioral-suite"},
    )["messageTemplate"]["messageTemplateId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: qc.delete_message_template(knowledgeBaseId=kb_id, messageTemplateId=template_id)
        )
    )

    rendered = qc.render_message_template(
        knowledgeBaseId=kb_id,
        messageTemplateId=template_id,
        attributes={"customAttributes": {"unused": "value"}},
    )

    actual = rendered["content"]["sms"]["body"]["plainText"]["content"]
    assert actual == body_text, f"expected verbatim body {body_text!r}, got {actual!r}"
    assert rendered.get("attributesNotInterpolated", []) == [], (
        "a template with no variables must report no unresolved attribute keys"
    )


def _create_active_knowledge_base(ctx, qc, kb_type: str) -> str:
    name = ctx.unique_name("sim2real-qc-kb-")
    kb_id = qc.create_knowledge_base(
        name=name, knowledgeBaseType=kb_type, tags={"sim2real-owner": "behavioral-suite"}
    )["knowledgeBase"]["knowledgeBaseId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: qc.delete_knowledge_base(knowledgeBaseId=kb_id)))
    status = _poll_until(
        lambda: qc.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]["status"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert status == "ACTIVE", f"knowledge base {kb_id} failed to activate, status={status!r}"
    return kb_id


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out after {timeout_s}s waiting for predicate, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
