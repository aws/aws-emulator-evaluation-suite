"""message-template-version-activate-deactivate."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "message-template-version-activate-deactivate"
GROUP = "state"
SERVICES = ["qconnect"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ActivateMessageTemplate/DeactivateMessageTemplate flip isActive on the numbered version only."""
    qc = ctx.client("qconnect")
    kb_id = _create_active_knowledge_base(ctx, qc, "MESSAGE_TEMPLATES")

    name = ctx.unique_name("sim2real-qc-tmpl-")
    template_id = qc.create_message_template(
        knowledgeBaseId=kb_id,
        name=name,
        channelSubtype="SMS",
        content={"sms": {"body": {"plainText": {"content": "Hello, this is a test message."}}}},
        tags={"team": "support", "stage": "sim2real-behav"},
    )["messageTemplate"]["messageTemplateId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: qc.delete_message_template(knowledgeBaseId=kb_id, messageTemplateId=template_id)
        )
    )

    version = qc.create_message_template_version(knowledgeBaseId=kb_id, messageTemplateId=template_id)[
        "messageTemplate"
    ]["versionNumber"]
    assert version == 1, f"first version created for a fresh template should be numbered 1, got {version}"

    qualified_id = f"{template_id}:{version}"
    before = qc.get_message_template(knowledgeBaseId=kb_id, messageTemplateId=qualified_id)["messageTemplate"]
    assert before["isActive"] is False, "freshly created version should not be active yet"

    qc.activate_message_template(knowledgeBaseId=kb_id, messageTemplateId=template_id, versionNumber=version)
    activated = qc.get_message_template(knowledgeBaseId=kb_id, messageTemplateId=qualified_id)["messageTemplate"]
    assert activated["isActive"] is True, "version should be active after ActivateMessageTemplate"

    qc.deactivate_message_template(knowledgeBaseId=kb_id, messageTemplateId=template_id, versionNumber=version)
    deactivated = qc.get_message_template(knowledgeBaseId=kb_id, messageTemplateId=qualified_id)["messageTemplate"]
    assert deactivated["isActive"] is False, "version should not be active after DeactivateMessageTemplate"


def _create_active_knowledge_base(ctx, qc, kb_type: str) -> str:
    name = ctx.unique_name("sim2real-qc-kb-")
    kb_id = qc.create_knowledge_base(
        name=name, knowledgeBaseType=kb_type, tags={"team": "support", "stage": "sim2real-behav"}
    )["knowledgeBase"]["knowledgeBaseId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: qc.delete_knowledge_base(knowledgeBaseId=kb_id)))
    status = _poll_until(
        lambda: qc.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]["status"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert status == "ACTIVE", f"knowledge base {kb_id} did not become ACTIVE, got {status}"
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
            raise AssertionError(f"timed out after {timeout_s}s waiting for predicate, last value was {value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
