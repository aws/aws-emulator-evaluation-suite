"""activate-nonexistent-template-version-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "activate-nonexistent-template-version-rejected"
GROUP = "overly-permissive"
SERVICES = ["qconnect"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ActivateMessageTemplate for a versionNumber that was never created is rejected."""
    qc = ctx.client("qconnect")
    kb_id = _create_active_knowledge_base(ctx, qc, "MESSAGE_TEMPLATES")

    name = ctx.unique_name("sim2real-qc-tmpl-")
    template_id = qc.create_message_template(
        knowledgeBaseId=kb_id,
        name=name,
        channelSubtype="SMS",
        content={"sms": {"body": {"plainText": {"content": "No version created yet"}}}},
        tags={"sim2real": CHECK},
    )["messageTemplate"]["messageTemplateId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: qc.delete_message_template(knowledgeBaseId=kb_id, messageTemplateId=template_id)
        )
    )

    code, message = _client_error(
        lambda: qc.activate_message_template(
            knowledgeBaseId=kb_id, messageTemplateId=template_id, versionNumber=1
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException for a nonexistent version, got {code}"
    assert message == "Message template version does not exist.", f"unexpected message {message!r}"

    listed = qc.list_message_template_versions(knowledgeBaseId=kb_id, messageTemplateId=template_id)[
        "messageTemplateVersionSummaries"
    ]
    assert listed == [], f"no version should have been created by the rejected activation, found {listed}"

    # positive control: create the version first, then activation succeeds
    version = qc.create_message_template_version(knowledgeBaseId=kb_id, messageTemplateId=template_id)[
        "messageTemplate"
    ]["versionNumber"]
    qc.activate_message_template(knowledgeBaseId=kb_id, messageTemplateId=template_id, versionNumber=version)
    activated = qc.get_message_template(
        knowledgeBaseId=kb_id, messageTemplateId=f"{template_id}:{version}"
    )["messageTemplate"]
    assert activated["isActive"] is True, "version should be active after activating a real, just-created version"


def _create_active_knowledge_base(ctx, qc, kb_type: str) -> str:
    name = ctx.unique_name("sim2real-qc-kb-")
    kb_id = qc.create_knowledge_base(
        name=name, knowledgeBaseType=kb_type, tags={"sim2real": CHECK}
    )["knowledgeBase"]["knowledgeBaseId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: qc.delete_knowledge_base(knowledgeBaseId=kb_id)))
    status = _poll_until(
        lambda: qc.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]["status"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
        reason="knowledge base to leave CREATING",
    )
    if status != "ACTIVE":
        raise AssertionError(f"knowledge base {kb_id} did not become ACTIVE, status={status}")
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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, reason="condition"):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    if not predicate(value):
        raise TimeoutError(f"timed out after {timeout_s}s waiting for {reason}, last value: {value!r}")
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
