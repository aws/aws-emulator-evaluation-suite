"""deploy-network-security-manager-waf-stack-reads-back-then-removed."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-network-security-manager-waf-stack-reads-back-then-removed"
GROUP = "deploy"
SERVICES = ["cloudformation", "network-security-manager"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_KINDS = (
    # (logical id, list op, list key, name key, arn key, get op, get identifier, id key)
    ("Rule", "list_rules", "rules", "ruleName", "ruleArn", "get_rule", "ruleIdentifier", "ruleId"),
    ("Template", "list_templates", "templates", "templateName", "templateArn", "get_template",
     "templateIdentifier", "templateId"),
    ("Policy", "list_policies", "policies", "policyName", "policyArn", "get_policy",
     "policyIdentifier", "policyId"),
    ("Scope", "list_scopes", "scopes", "scopeName", "scopeArn", "get_scope", "scopeIdentifier",
     "scopeId"),
)


@tags(
    "axis:happy-path", "cap:c1", "concern:deploy", "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation-deployed rule, template, policy and scope are real at Network Security
    Manager: Ref, every Fn::GetAtt, every declared property and the tags match an independent
    List*/Get* read, and deleting the stack removes all four from the service, not just CFN."""
    cfn = ctx.client("cloudformation")
    nsm = ctx.client("network-security-manager")

    stack_name = ctx.unique_name("sim2real-behav-cfn-nsm-")
    rule_name = ctx.unique_name("sim2real-behav-nsm-rule-")
    template_name = ctx.unique_name("sim2real-behav-nsm-tmpl-")
    policy_name = ctx.unique_name("sim2real-behav-nsm-pol-")
    scope_name = ctx.unique_name("sim2real-behav-nsm-scope-")
    # Priority is drawn per run from the name, so sibling runs do not share one.
    priority = int(policy_name[-8:], 16) % 9000 + 1000

    rule_config = {"DefaultAction": {"Allow": {}}}
    scope_config = {"ResourceScopes": {"AWS::EC2::EIP": {"IncludeAll": True}}}

    template = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Rule": {
                "Type": "AWS::NetworkSecurityManager::Rule",
                "Properties": {
                    "RuleName": rule_name,
                    "FirewallType": "WAF",
                    "RuleType": "CONFIGURATION",
                    "Configuration": json.dumps(rule_config),
                    "Tags": [{"Key": "sim2real-nsm", "Value": rule_name}],
                },
            },
            "Template": {
                "Type": "AWS::NetworkSecurityManager::Template",
                "Properties": {
                    "TemplateName": template_name,
                    "FirewallType": "WAF",
                    "AssociatedRuleList": [{"RuleArn": {"Fn::GetAtt": ["Rule", "RuleArn"]}}],
                    "Tags": [{"Key": "sim2real-nsm", "Value": template_name}],
                },
            },
            "Policy": {
                "Type": "AWS::NetworkSecurityManager::Policy",
                "Properties": {
                    "PolicyName": policy_name,
                    "FirewallType": "WAF",
                    "Priority": priority,
                    "AssociatedTemplateAndRuleList": [
                        {"TemplateArn": {"Fn::GetAtt": ["Template", "TemplateArn"]}}
                    ],
                    "PolicyConfiguration": {
                        "RemediationEnabled": False,
                        "ResourcesCleanUp": True,
                        "WafConfig": {
                            "ExistingCustomerWebACLResolution": "RETROFIT",
                            "ConflictResolution": "MERGE_WHERE_APPLICABLE",
                        },
                    },
                    "Tags": [{"Key": "sim2real-nsm", "Value": policy_name}],
                },
            },
            "Scope": {
                "Type": "AWS::NetworkSecurityManager::Scope",
                "Properties": {
                    "ScopeName": scope_name,
                    "ScopeConfiguration": json.dumps(scope_config),
                    "Tags": [{"Key": "sim2real-nsm", "Value": scope_name}],
                },
            },
        },
        "Outputs": {
            "RuleRef": {"Value": {"Ref": "Rule"}},
            "TemplateRef": {"Value": {"Ref": "Template"}},
            "PolicyRef": {"Value": {"Ref": "Policy"}},
            "ScopeRef": {"Value": {"Ref": "Scope"}},
            "RuleArn": {"Value": {"Fn::GetAtt": ["Rule", "RuleArn"]}},
            "RuleId": {"Value": {"Fn::GetAtt": ["Rule", "RuleId"]}},
            "RuleStatus": {"Value": {"Fn::GetAtt": ["Rule", "Status"]}},
            "TemplateArn": {"Value": {"Fn::GetAtt": ["Template", "TemplateArn"]}},
            "TemplateId": {"Value": {"Fn::GetAtt": ["Template", "TemplateId"]}},
            "TemplateStatus": {"Value": {"Fn::GetAtt": ["Template", "Status"]}},
            "PolicyArn": {"Value": {"Fn::GetAtt": ["Policy", "PolicyArn"]}},
            "PolicyId": {"Value": {"Fn::GetAtt": ["Policy", "PolicyId"]}},
            "PolicyStatus": {"Value": {"Fn::GetAtt": ["Policy", "Status"]}},
            "ScopeArn": {"Value": {"Fn::GetAtt": ["Scope", "ScopeArn"]}},
            "ScopeId": {"Value": {"Fn::GetAtt": ["Scope", "ScopeId"]}},
            "ScopeStatus": {"Value": {"Fn::GetAtt": ["Scope", "Status"]}},
        },
    })

    stack_id = create_stack(ctx, cfn, stack_name, template)
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    names = {"Rule": rule_name, "Template": template_name, "Policy": policy_name,
             "Scope": scope_name}

    # Ref and GetAtt *Arn == the ARN an independent List* by name returns; GetAtt *Id and Status
    # == the Get* by that ARN; the declared name and tags read back for each type.
    arns, got = {}, {}
    for kind, list_op, key, name_key, arn_key, get_op, ident, id_key in _KINDS:
        listed = [i[arn_key] for i in paginate(nsm, list_op, key) if i[name_key] == names[kind]]
        assert listed == [outputs[f"{kind}Ref"]] == [outputs[f"{kind}Arn"]], (
            f"{list_op} by name {listed!r}, Ref {outputs[f'{kind}Ref']!r}, "
            f"GetAtt {kind}Arn {outputs[f'{kind}Arn']!r}"
        )
        arns[kind] = listed[0]
        got[kind] = getattr(nsm, get_op)(**{ident: listed[0]})
        read = (got[kind][name_key], got[kind][id_key], got[kind]["status"])
        want = (names[kind], outputs[f"{kind}Id"], "ACTIVE")
        assert read == want == (want[0], want[1], outputs[f"{kind}Status"]), (
            f"{kind} reads (name, id, status) {read!r}, GetAtts {want!r}"
        )
        res_tags = {k: v for k, v in nsm.list_tags_for_resource(resourceArn=listed[0])["tags"].items()
                    if not k.startswith("aws:")}
        assert res_tags == {"sim2real": stack_name, "sim2real-nsm": names[kind]}, (
            f"{kind} tags {res_tags!r}"
        )

    rule = got["Rule"]
    read = (rule["firewallType"], rule["ruleType"], rule["configuration"])
    assert read == ("WAF", "CONFIGURATION", rule_config), f"rule reads {read!r}"
    tmpl = got["Template"]
    read = (tmpl["firewallType"], tmpl["associatedRuleList"])
    assert read == ("WAF", [{"ruleArn": arns["Rule"]}]), f"template reads {read!r}"
    policy = got["Policy"]
    read = (policy["firewallType"], policy["priority"], policy["associatedTemplateAndRuleList"],
            policy["policyConfiguration"])
    want = ("WAF", priority, [{"templateArn": arns["Template"]}], {
        "remediationEnabled": False,
        "resourcesCleanUp": True,
        "wafConfig": {
            "existingCustomerWebACLResolution": "RETROFIT",
            "conflictResolution": "MERGE_WHERE_APPLICABLE",
        },
    })
    assert read == want, f"policy reads {read!r}, expected {want!r}"
    scope = got["Scope"]["scopeConfiguration"]
    assert scope == {"resourceScopes": {"AWS::EC2::EIP": {"includeAll": True}}}, (
        f"scope configuration {scope!r}"
    )

    # Each resource is gone from Network Security Manager, not merely from the stack.
    delete_stack(cfn, stack_id)
    for kind, list_op, key, name_key, _arn_key, get_op, ident, _id_key in _KINDS:
        own_id = arns[kind].rsplit(":", 1)[-1]
        expect_error(lambda: getattr(nsm, get_op)(**{ident: arns[kind]}),  # noqa: B023
                     *("ResourceNotFoundException", f"{kind} not found: {own_id}"))
        remaining = [i[name_key] for i in paginate(nsm, list_op, key) if i[name_key] == names[kind]]
        assert remaining == [], f"{list_op} still lists {names[kind]!r} after the stack delete"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
