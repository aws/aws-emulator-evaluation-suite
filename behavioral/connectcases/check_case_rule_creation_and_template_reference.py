"""case-rule-creation-and-template-reference."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "case-rule-creation-and-template-reference"
GROUP = "data-plane"
SERVICES = ["connectcases"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A case rule created via CreateCaseRule is retrievable via ListCaseRules and
    BatchGetCaseRule, and once attached to a template's `rules` list (associated with a
    specific field), GetTemplate reflects that exact caseRuleId/fieldId association."""
    cc = ctx.client("connectcases")
    domain_id = _create_active_domain(ctx)
    text_field = _create_field(ctx, domain_id, "Text", "text")

    rule_name = ctx.unique_name("sim2real-cc-rule-")
    case_rule_resp = cc.create_case_rule(
        domainId=domain_id,
        name=rule_name,
        rule={
            "required": {
                "defaultValue": False,
                "conditions": [
                    {
                        "equalTo": {
                            "operandOne": {"fieldId": text_field},
                            "operandTwo": {"stringValue": "sim2real-trigger"},
                            "result": True,
                        }
                    }
                ],
            }
        },
    )
    case_rule_id = case_rule_resp["caseRuleId"]
    cc.tag_resource(arn=case_rule_resp["caseRuleArn"], tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: cc.delete_case_rule(domainId=domain_id, caseRuleId=case_rule_id))

    listed = cc.list_case_rules(domainId=domain_id)["caseRules"]
    assert any(r["caseRuleId"] == case_rule_id and r["name"] == rule_name for r in listed), (
        f"case rule {case_rule_id} ({rule_name!r}) not found in list_case_rules: {listed}"
    )

    batch = cc.batch_get_case_rule(domainId=domain_id, caseRules=[{"id": case_rule_id}])
    assert batch["errors"] == [], f"expected no batch-get errors, got {batch['errors']}"
    assert len(batch["caseRules"]) == 1, f"expected exactly one case rule, got {batch['caseRules']}"
    assert batch["caseRules"][0]["caseRuleId"] == case_rule_id, (
        f"expected caseRuleId {case_rule_id}, got {batch['caseRules'][0]['caseRuleId']}"
    )
    assert batch["caseRules"][0]["name"] == rule_name, (
        f"expected name {rule_name!r}, got {batch['caseRules'][0]['name']!r}"
    )

    template_id = _create_template(
        ctx, domain_id, rules=[{"caseRuleId": case_rule_id, "fieldId": text_field}]
    )
    template = cc.get_template(domainId=domain_id, templateId=template_id)
    rules = template["rules"]
    assert len(rules) == 1, f"expected exactly one rule on template, got {rules}"
    assert rules[0]["caseRuleId"] == case_rule_id, (
        f"expected caseRuleId {case_rule_id} on template rule, got {rules[0]['caseRuleId']}"
    )
    assert rules[0]["fieldId"] == text_field, (
        f"expected fieldId {text_field} on template rule, got {rules[0]['fieldId']}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _delete_domain(ctx, domain_id):
    cc = ctx.client("connectcases")
    for _ in range(5):
        try:
            cc.delete_domain(domainId=domain_id)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "ConflictException":
                raise
            time.sleep(3.0)
    cc.delete_domain(domainId=domain_id)


def _create_active_domain(ctx):
    cc = ctx.client("connectcases")
    name = ctx.unique_name("sim2real-cc-domain-")
    domain_resp = cc.create_domain(name=name)
    domain_id = domain_resp["domainId"]
    cc.tag_resource(arn=domain_resp["domainArn"], tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: _delete_domain(ctx, domain_id))
    status = _poll_until(
        lambda: cc.get_domain(domainId=domain_id)["domainStatus"],
        lambda s: s != "CreationInProgress",
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert status == "Active", f"domain reached terminal status {status!r}, expected Active"
    return domain_id


def _create_field(ctx, domain_id, field_type, name_prefix="field"):
    cc = ctx.client("connectcases")
    name = ctx.unique_name(f"sim2real-cc-{name_prefix}-")
    field_resp = cc.create_field(domainId=domain_id, name=name, type=field_type)
    field_id = field_resp["fieldId"]
    cc.tag_resource(arn=field_resp["fieldArn"], tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: cc.delete_field(domainId=domain_id, fieldId=field_id))
    return field_id


def _create_template(ctx, domain_id, required_field_ids=None, rules=None, status="Active"):
    cc = ctx.client("connectcases")
    name = ctx.unique_name("sim2real-cc-template-")
    kwargs = {"domainId": domain_id, "name": name, "status": status}
    if required_field_ids:
        kwargs["requiredFields"] = [{"fieldId": fid} for fid in required_field_ids]
    if rules:
        kwargs["rules"] = rules
    template_resp = cc.create_template(**kwargs)
    template_id = template_resp["templateId"]
    cc.tag_resource(arn=template_resp["templateArn"], tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: cc.delete_template(domainId=domain_id, templateId=template_id))
    return template_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
