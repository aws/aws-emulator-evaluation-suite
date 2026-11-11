"""eventbridge-rule-template-group-hierarchy-crud."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-rule-template-group-hierarchy-crud"
GROUP = "resource-lifecycle"
SERVICES = ["medialive"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An EventBridge rule template lives inside a template group; a non-empty group cannot be
    deleted, update/get/delete all respect that hierarchy, and both levels are provably gone."""
    medialive = ctx.client("medialive")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    target_arn = f"arn:aws:sns:{ctx.region}:{account_id}:sim2real-medialive-fake-topic"
    resource_tags = {"sim2real-check": "eventbridge-rule-template-group-hierarchy-crud"}

    group = medialive.create_event_bridge_rule_template_group(
        Name=ctx.unique_name("sim2real-medialive-ebgrp-"), Tags=resource_tags
    )
    group_id = group["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: medialive.delete_event_bridge_rule_template_group(Identifier=group_id)))

    template_name = ctx.unique_name("sim2real-medialive-ebtpl-")
    template = medialive.create_event_bridge_rule_template(
        Name=template_name,
        GroupIdentifier=group_id,
        EventType="MEDIALIVE_CHANNEL_ALERT",
        EventTargets=[{"Arn": target_arn}],
        Tags=resource_tags,
    )
    template_id = template["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: medialive.delete_event_bridge_rule_template(Identifier=template_id)))
    assert template["GroupId"] == group_id, f"expected template GroupId {group_id!r}, got {template['GroupId']!r}"
    assert template["EventType"] == "MEDIALIVE_CHANNEL_ALERT", (
        f"expected EventType 'MEDIALIVE_CHANNEL_ALERT', got {template['EventType']!r}"
    )

    # Hierarchy enforcement, six beats: positive control above (group + template exist) -> break
    # exactly one thing (delete the group while it still owns a template) -> specific error ->
    # effect absent via independent reads at both levels -> restore (delete the template) ->
    # the identical delete-group call now succeeds (asserted further down).
    conflict_code, conflict_message = _client_error(
        lambda: medialive.delete_event_bridge_rule_template_group(Identifier=group_id),
        "DeleteEventBridgeRuleTemplateGroup on a non-empty group",
    )
    assert conflict_code == "ConflictException", (
        f"expected ConflictException deleting a non-empty group, got {conflict_code!r}"
    )
    assert conflict_message == "Template group must be empty before deletion.", conflict_message
    still_group = medialive.get_event_bridge_rule_template_group(Identifier=group_id)
    assert still_group["Id"] == group_id, "group must still exist after the rejected delete"
    still_template = medialive.get_event_bridge_rule_template(Identifier=template_id)
    assert still_template["GroupId"] == group_id, "template must still exist, still owned by the group"

    other_target = f"arn:aws:sns:{ctx.region}:{account_id}:sim2real-medialive-fake-topic-2"
    medialive.update_event_bridge_rule_template(Identifier=template_id, EventTargets=[{"Arn": other_target}])
    fetched = medialive.get_event_bridge_rule_template(Identifier=template_id)
    assert fetched["EventTargets"] == [{"Arn": other_target}], (
        f"expected EventTargets [{{'Arn': {other_target!r}}}], got {fetched['EventTargets']!r}"
    )

    medialive.delete_event_bridge_rule_template(Identifier=template_id)
    # AWS answers these NotFoundExceptions with a null message, so the exact message is None.
    code, message = _client_error(
        lambda: medialive.get_event_bridge_rule_template(Identifier=template_id), "GetEventBridgeRuleTemplate after delete"
    )
    assert code == "NotFoundException", f"expected NotFoundException reading deleted template, got {code!r}"
    assert message is None, f"expected no message reading deleted template, got {message!r}"
    update_after_delete, update_message = _client_error(
        lambda: medialive.update_event_bridge_rule_template(Identifier=template_id, EventTargets=[{"Arn": target_arn}]),
        "UpdateEventBridgeRuleTemplate after delete",
    )
    assert update_after_delete == "NotFoundException", (
        f"expected NotFoundException updating deleted template, got {update_after_delete!r}"
    )
    assert update_message is None, f"expected no message updating deleted template, got {update_message!r}"

    # Restore + identical call succeeds: the group is empty now, so the delete that was just
    # rejected must go through.
    medialive.delete_event_bridge_rule_template_group(Identifier=group_id)
    group_code, group_message = _client_error(
        lambda: medialive.get_event_bridge_rule_template_group(Identifier=group_id),
        "GetEventBridgeRuleTemplateGroup after delete",
    )
    assert group_code == "NotFoundException", f"expected NotFoundException reading deleted group, got {group_code!r}"
    assert group_message is None, f"expected no message reading deleted group, got {group_message!r}"


def _client_error(fn, description):
    """Call fn() and return its (code, message). An unexpected success raises, so an emulator
    accepting what AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"].get("Code"), e.response["Error"].get("Message")
    raise AssertionError(f"expected {description} to be rejected, but it succeeded: {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
