"""update-activated-message-template-version-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-activated-message-template-version-rejected"
GROUP = "overly-permissive"
SERVICES = ["qconnect"]

_QUALIFIED_ID_REFUSAL = (
    "1 validation error detected: Value at 'messageTemplateId' failed to satisfy constraint: "
    "Member must satisfy regular expression pattern: "
    '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$|^arn:[a-z-]*?:wisdom:[a-z0-9-]*?:[0-9]{12}:[a-z-]*?/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}(?:/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}){0,2}'
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateMessageTemplate against an activated numbered version is refused: the id pattern admits no
    version qualifier, so a published version is immutable; $LATEST stays editable."""
    qc = ctx.client("qconnect")
    kb_id = _create_active_knowledge_base(ctx, qc, "MESSAGE_TEMPLATES")

    name = ctx.unique_name("sim2real-qc-tmpl-")
    template_id = qc.create_message_template(
        knowledgeBaseId=kb_id,
        name=name,
        channelSubtype="SMS",
        content={"sms": {"body": {"plainText": {"content": "Original latest content"}}}},
    )["messageTemplate"]["messageTemplateId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: qc.delete_message_template(knowledgeBaseId=kb_id, messageTemplateId=template_id)
        )
    )
    version = qc.create_message_template_version(knowledgeBaseId=kb_id, messageTemplateId=template_id)[
        "messageTemplate"
    ]["versionNumber"]
    qc.activate_message_template(knowledgeBaseId=kb_id, messageTemplateId=template_id, versionNumber=version)

    qualified_id = f"{template_id}:{version}"
    code, message = _client_error(
        lambda: qc.update_message_template(
            knowledgeBaseId=kb_id,
            messageTemplateId=qualified_id,
            content={"sms": {"body": {"plainText": {"content": "Attempted mutation of a published version"}}}},
        )
    )
    assert code == "ValidationException", f"expected ValidationException mutating a published version, got {code}"
    assert message == _QUALIFIED_ID_REFUSAL, f"unexpected message {message!r}"

    unchanged = qc.get_message_template(knowledgeBaseId=kb_id, messageTemplateId=qualified_id)["messageTemplate"]
    assert unchanged["content"]["sms"]["body"]["plainText"]["content"] == "Original latest content"

    # positive control: mutating $LATEST (unqualified id) still works
    qc.update_message_template(
        knowledgeBaseId=kb_id,
        messageTemplateId=template_id,
        content={"sms": {"body": {"plainText": {"content": "New latest content"}}}},
    )
    latest = qc.get_message_template(knowledgeBaseId=kb_id, messageTemplateId=template_id)["messageTemplate"]
    assert latest["content"]["sms"]["body"]["plainText"]["content"] == "New latest content"


def _create_active_knowledge_base(ctx, qc, kb_type: str) -> str:
    name = ctx.unique_name("sim2real-qc-kb-")
    kb_id = qc.create_knowledge_base(name=name, knowledgeBaseType=kb_type)["knowledgeBase"]["knowledgeBaseId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: qc.delete_knowledge_base(knowledgeBaseId=kb_id)))
    status = _poll_until(
        lambda: qc.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]["status"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert status == "ACTIVE", f"knowledge base did not become ACTIVE, status={status}"
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
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last saw {value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
