"""approval-rule-template-empty-description-normalized-to-absent."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "approval-rule-template-empty-description-normalized-to-absent"
GROUP = "representation"
SERVICES = ["codecommit"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A non-empty template description round-trips exactly; a never-set one and one reset to ""
    both read back falsy and identical, and a later real update on the never-set one round-trips.
    """
    cc = ctx.client("codecommit")
    rule_content = (
        '{"Version":"2018-11-08","DestinationReferences":["refs/heads/main"],'
        '"Statements":[{"Type":"Approvers","NumberOfApprovalsNeeded":1}]}'
    )

    name_explicit = ctx.unique_name("sim2real-cc-tpl-explicit-")
    name_absent = ctx.unique_name("sim2real-cc-tpl-absent-")

    real_description = "a real description with unicode caf\u00e9 \u2014 v1"
    cc.create_approval_rule_template(
        approvalRuleTemplateName=name_explicit,
        approvalRuleTemplateContent=rule_content,
        approvalRuleTemplateDescription=real_description,
    )
    ctx.on_cleanup(
        lambda: cc.delete_approval_rule_template(approvalRuleTemplateName=name_explicit)
    )

    cc.create_approval_rule_template(
        approvalRuleTemplateName=name_absent,
        approvalRuleTemplateContent=rule_content,
    )
    ctx.on_cleanup(
        lambda: cc.delete_approval_rule_template(approvalRuleTemplateName=name_absent)
    )

    tpl_explicit = cc.get_approval_rule_template(
        approvalRuleTemplateName=name_explicit
    )["approvalRuleTemplate"]
    assert tpl_explicit.get("approvalRuleTemplateDescription") == real_description, (
        f"expected {real_description!r} to round-trip byte-for-byte, "
        f"got {tpl_explicit.get('approvalRuleTemplateDescription')!r}"
    )

    tpl_absent = cc.get_approval_rule_template(approvalRuleTemplateName=name_absent)[
        "approvalRuleTemplate"
    ]
    assert not tpl_absent.get("approvalRuleTemplateDescription"), tpl_absent

    cc.update_approval_rule_template_description(
        approvalRuleTemplateName=name_explicit, approvalRuleTemplateDescription=""
    )
    tpl_explicit_after = cc.get_approval_rule_template(
        approvalRuleTemplateName=name_explicit
    )["approvalRuleTemplate"]
    assert not tpl_explicit_after.get("approvalRuleTemplateDescription"), tpl_explicit_after

    assert tpl_explicit_after.get("approvalRuleTemplateDescription") == tpl_absent.get(
        "approvalRuleTemplateDescription"
    ), (
        f"expected reset-to-empty template's description "
        f"({tpl_explicit_after.get('approvalRuleTemplateDescription')!r}) to match "
        f"never-set template's description ({tpl_absent.get('approvalRuleTemplateDescription')!r})"
    )

    cc.update_approval_rule_template_description(
        approvalRuleTemplateName=name_absent,
        approvalRuleTemplateDescription="now set for real",
    )
    tpl_absent_after = cc.get_approval_rule_template(approvalRuleTemplateName=name_absent)[
        "approvalRuleTemplate"
    ]
    assert tpl_absent_after.get("approvalRuleTemplateDescription") == "now set for real", (
        f"expected description 'now set for real' after update, "
        f"got {tpl_absent_after.get('approvalRuleTemplateDescription')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

