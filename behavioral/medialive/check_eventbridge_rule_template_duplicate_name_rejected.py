"""eventbridge-rule-template-duplicate-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "eventbridge-rule-template-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["medialive"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEventBridgeRuleTemplate rejects a name that collides with an existing template in the same group."""
    medialive = ctx.client("medialive")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    target_arn = f"arn:aws:sns:{ctx.region}:{account_id}:sim2real-medialive-fake-topic"

    group = medialive.create_event_bridge_rule_template_group(
        Name=ctx.unique_name("sim2real-medialive-ebgrp-"),
        Tags={"sim2real:managed": "true"},
    )
    group_id = group["Id"]
    ctx.on_cleanup(lambda: medialive.delete_event_bridge_rule_template_group(Identifier=group_id))

    template_name = ctx.unique_name("sim2real-medialive-ebtpl-")
    template = medialive.create_event_bridge_rule_template(
        Name=template_name,
        GroupIdentifier=group_id,
        EventType="MEDIALIVE_CHANNEL_STATE_CHANGE",
        EventTargets=[{"Arn": target_arn}],
        Tags={"sim2real:managed": "true"},
    )
    template_id = template["Id"]
    ctx.on_cleanup(lambda: medialive.delete_event_bridge_rule_template(Identifier=template_id))

    code, message = _client_error(
        lambda: medialive.create_event_bridge_rule_template(
            Name=template_name,
            GroupIdentifier=group_id,
            EventType="MEDIALIVE_CHANNEL_STATE_CHANGE",
            EventTargets=[{"Arn": target_arn}],
        ),
        "CreateEventBridgeRuleTemplate with a duplicate name",
    )
    assert code == "ConflictException", f"expected ConflictException for a duplicate name, got {code!r}"
    assert message == "Name already in use", message

    # Effect absent: exactly one template with this name exists in the group.
    templates = medialive.list_event_bridge_rule_templates(GroupIdentifier=group_id)["EventBridgeRuleTemplates"]
    matching = [t for t in templates if t["Name"] == template_name]
    assert len(matching) == 1, matching

    # Positive control: a different name in the same group succeeds.
    other_name = ctx.unique_name("sim2real-medialive-ebtpl-other-")
    other_template = medialive.create_event_bridge_rule_template(
        Name=other_name,
        GroupIdentifier=group_id,
        EventType="MEDIALIVE_CHANNEL_STATE_CHANGE",
        EventTargets=[{"Arn": target_arn}],
        Tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: medialive.delete_event_bridge_rule_template(Identifier=other_template["Id"]))
    assert other_template["Name"] == other_name, other_template

    # Terminal read: independent of every create above (list, not the create response) —
    # both the original and the positive-control template are visible at the destination.
    final_templates = medialive.list_event_bridge_rule_templates(GroupIdentifier=group_id)["EventBridgeRuleTemplates"]
    final_names = {t["Name"] for t in final_templates}
    assert {template_name, other_name} <= final_names, final_names


def _client_error(fn, description):
    """Call fn() and return its (code, message). An unexpected success raises, so an emulator
    accepting what AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"].get("Code"), e.response["Error"].get("Message")
    raise AssertionError(f"expected {description} to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
