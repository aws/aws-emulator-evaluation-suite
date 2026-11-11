"""message-template-attachment-round-trip."""
from __future__ import annotations

import base64
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "message-template-attachment-round-trip"
GROUP = "data-plane"
SERVICES = ["qconnect"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateMessageTemplateAttachment appears on GetMessageTemplate and disappears after deletion."""
    qc = ctx.client("qconnect")
    kb_id = _create_active_knowledge_base(ctx, qc, "MESSAGE_TEMPLATES")

    name = ctx.unique_name("sim2real-qc-tmpl-")
    template_id = qc.create_message_template(
        knowledgeBaseId=kb_id,
        name=name,
        channelSubtype="EMAIL",
        content={
            "email": {
                "subject": "Your receipt",
                "body": {"plainText": {"content": "Please find your receipt attached."}},
            }
        },
        tags={"sim2real": CHECK},
    )["messageTemplate"]["messageTemplateId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: qc.delete_message_template(knowledgeBaseId=kb_id, messageTemplateId=template_id)
        )
    )

    encoded_body = base64.b64encode(b"fake receipt bytes").decode("ascii")
    attachment = qc.create_message_template_attachment(
        knowledgeBaseId=kb_id,
        messageTemplateId=template_id,
        contentDisposition="ATTACHMENT",
        name="receipt.pdf",
        body=encoded_body,
    )["attachment"]
    attachment_id = attachment["attachmentId"]

    after_create = qc.get_message_template(knowledgeBaseId=kb_id, messageTemplateId=template_id)["messageTemplate"]
    ids_after_create = {a["attachmentId"] for a in after_create.get("attachments", [])}
    assert attachment_id in ids_after_create, f"attachment {attachment_id} missing from {ids_after_create}"

    qc.delete_message_template_attachment(
        knowledgeBaseId=kb_id, messageTemplateId=template_id, attachmentId=attachment_id
    )

    after_delete = qc.get_message_template(knowledgeBaseId=kb_id, messageTemplateId=template_id)["messageTemplate"]
    ids_after_delete = {a["attachmentId"] for a in after_delete.get("attachments", [])}
    assert attachment_id not in ids_after_delete, f"attachment {attachment_id} still present in {ids_after_delete}"

    try:
        qc.delete_message_template_attachment(
            knowledgeBaseId=kb_id, messageTemplateId=template_id, attachmentId=attachment_id
        )
    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        assert error_code == "ConflictException", (
            f"expected ConflictException re-deleting gone attachment {attachment_id}, got {error_code}"
        )
        error_message = exc.response["Error"].get("Message")
        assert error_message == (
            "Unable to delete message template attachment: there is conflict in the current state of resource"
        ), f"unexpected message {error_message!r}"
    else:
        raise AssertionError(f"re-deleting already-deleted attachment {attachment_id} unexpectedly succeeded")


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
    assert status == "ACTIVE", f"knowledge base {kb_id} did not become ACTIVE, status {status}"
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
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    if not predicate(value):
        raise TimeoutError(f"timed out after {timeout_s}s waiting for predicate, last value {value!r}")
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
