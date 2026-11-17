"""create-template-and-scope-appear-by-id-in-their-lists."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-template-and-scope-appear-by-id-in-their-lists"
GROUP = "representation"
SERVICES = ["network-security-manager"]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A created template's id appears in ListTemplates with its exact name, ARN and
    firewall type; a created scope's id appears in ListScopes with its exact name and ARN.
    """
    nsm = ctx.client("network-security-manager")
    rule_name = ctx.unique_name("sim2real-behav-nsm-rule-")
    template_name = ctx.unique_name("sim2real-behav-nsm-tmpl-")
    scope_name = ctx.unique_name("sim2real-behav-nsm-scope-")

    rule = nsm.create_rule(
        ruleName=rule_name,
        firewallType="WAF",
        ruleType="CONFIGURATION",
        configuration={"DefaultAction": {"Allow": {}}},
        isPublished=True,
    )
    rule_arn = rule["ruleArn"]
    ctx.on_cleanup(
        _teardown(lambda: nsm.delete_rule(ruleIdentifier=rule_arn), "ResourceNotFoundException")
    )

    template = nsm.create_template(
        templateName=template_name,
        firewallType="WAF",
        associatedRuleList=[{"ruleIdentifier": rule_arn}],
        isPublished=True,
    )
    template_id = template["templateId"]
    template_arn = template["templateArn"]
    ctx.on_cleanup(
        _teardown(
            lambda: nsm.delete_template(templateIdentifier=template_arn),
            "ResourceNotFoundException",
        )
    )

    scope = nsm.create_scope(
        scopeName=scope_name,
        scopeConfiguration={"resourceScopes": {"AWS::EC2::EIP": {"includeAll": True}}},
        isPublished=True,
    )
    scope_id = scope["scopeId"]
    scope_arn = scope["scopeArn"]
    ctx.on_cleanup(
        _teardown(lambda: nsm.delete_scope(scopeIdentifier=scope_arn), "ResourceNotFoundException")
    )

    templates_by_id = {}
    for page in nsm.get_paginator("list_templates").paginate():
        for entry in page["templates"]:
            templates_by_id[entry["templateId"]] = entry
    assert template_id in templates_by_id, (
        f"ListTemplates did not include the created template id {template_id!r}"
    )
    listed_template = templates_by_id[template_id]
    assert listed_template["templateName"] == template_name, (
        f"ListTemplates entry for {template_id!r} had templateName "
        f"{listed_template['templateName']!r}, expected {template_name!r}"
    )
    assert listed_template["templateArn"] == template_arn, (
        f"ListTemplates entry for {template_id!r} had templateArn "
        f"{listed_template['templateArn']!r}, expected {template_arn!r}"
    )
    assert listed_template["firewallType"] == "WAF", (
        f"ListTemplates entry for {template_id!r} had firewallType "
        f"{listed_template['firewallType']!r}, expected 'WAF'"
    )

    scopes_by_id = {}
    for page in nsm.get_paginator("list_scopes").paginate():
        for entry in page["scopes"]:
            scopes_by_id[entry["scopeId"]] = entry
    assert scope_id in scopes_by_id, f"ListScopes did not include the created scope id {scope_id!r}"
    listed_scope = scopes_by_id[scope_id]
    assert listed_scope["scopeName"] == scope_name, (
        f"ListScopes entry for {scope_id!r} had scopeName {listed_scope['scopeName']!r}, "
        f"expected {scope_name!r}"
    )
    assert listed_scope["scopeArn"] == scope_arn, (
        f"ListScopes entry for {scope_id!r} had scopeArn {listed_scope['scopeArn']!r}, "
        f"expected {scope_arn!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
