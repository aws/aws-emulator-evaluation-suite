"""deploy-network-security-manager-policy-ambiguous-reference-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-network-security-manager-policy-ambiguous-reference-rejected"
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
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


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


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


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

_REJECTED = (
    "Each AssociatedTemplateAndRuleList entry must specify exactly one of TemplateArn or RuleArn.",
    "InvalidRequest",
)


def _names(nsm, op, key, name_key):
    return [item[name_key] for item in paginate(nsm, op, key)]


def _stack(resources):
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources})


def _rule_template(rule_name: str, template_name: str) -> dict:
    return {
        "Rule": {
            "Type": "AWS::NetworkSecurityManager::Rule",
            "Properties": {
                "RuleName": rule_name,
                "FirewallType": "WAF",
                "RuleType": "CONFIGURATION",
                "Configuration": json.dumps({"DefaultAction": {"Allow": {}}}),
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
    }


def _policy_properties(policy_name: str, priority: int, associated: list[dict]) -> dict:
    return {
        "PolicyName": policy_name,
        "FirewallType": "WAF",
        "Priority": priority,
        "AssociatedTemplateAndRuleList": associated,
        "PolicyConfiguration": {
            "RemediationEnabled": False,
            "ResourcesCleanUp": True,
            "WafConfig": {
                "ExistingCustomerWebACLResolution": "RETROFIT",
                "ConflictResolution": "MERGE_WHERE_APPLICABLE",
            },
        },
        "Tags": [{"Key": "sim2real-nsm", "Value": policy_name}],
    }


@tags(
    "axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A Policy whose AssociatedTemplateAndRuleList entry names both a template and a rule rolls
    back with Network Security Manager's exact rejection and no policy ever created, while the
    same template with the entry naming only the template deploys and reads back."""
    cfn = ctx.client("cloudformation")
    nsm = ctx.client("network-security-manager")

    bad_rule_name = ctx.unique_name("sim2real-behav-nsm-badrule-")
    bad_template_name = ctx.unique_name("sim2real-behav-nsm-badtmpl-")
    bad_policy_name = ctx.unique_name("sim2real-behav-nsm-badpol-")
    # Priority is drawn per run from the name, so sibling runs do not share one.
    bad_priority = int(bad_policy_name[-8:], 16) % 9000 + 1000

    bad_resources = _rule_template(bad_rule_name, bad_template_name)
    bad_resources["Policy"] = {
        "Type": "AWS::NetworkSecurityManager::Policy",
        "Properties": _policy_properties(
            bad_policy_name,
            bad_priority,
            [{
                "TemplateArn": {"Fn::GetAtt": ["Template", "TemplateArn"]},
                "RuleArn": {"Fn::GetAtt": ["Rule", "RuleArn"]},
            }],
        ),
    }
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-cfn-nsmbad-"),
                          _stack(bad_resources))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "Policy"), ctx.account)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"

    # Rollback absence through Network Security Manager by the declared names, before any delete.
    for op, key, name_key, name in (("list_policies", "policies", "policyName", bad_policy_name),
                                    ("list_templates", "templates", "templateName",
                                     bad_template_name),
                                    ("list_rules", "rules", "ruleName", bad_rule_name)):
        listed = [n for n in _names(nsm, op, key, name_key) if n == name]
        assert listed == [], f"{op} lists the rolled-back {name!r}"

    # Positive control: the same resources with the entry naming only the template.
    good_rule_name = ctx.unique_name("sim2real-behav-nsm-okrule-")
    good_template_name = ctx.unique_name("sim2real-behav-nsm-oktmpl-")
    good_policy_name = ctx.unique_name("sim2real-behav-nsm-okpol-")
    good_priority = int(good_policy_name[-8:], 16) % 9000 + 1000

    good_resources = _rule_template(good_rule_name, good_template_name)
    good_resources["Policy"] = {
        "Type": "AWS::NetworkSecurityManager::Policy",
        "Properties": _policy_properties(
            good_policy_name,
            good_priority,
            [{"TemplateArn": {"Fn::GetAtt": ["Template", "TemplateArn"]}}],
        ),
    }
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-cfn-nsmok-"),
                           _stack(good_resources))
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"

    policies = [p["policyArn"] for p in paginate(nsm, "list_policies", "policies")
                if p["policyName"] == good_policy_name]
    templates = [t["templateArn"] for t in paginate(nsm, "list_templates", "templates")
                 if t["templateName"] == good_template_name]
    assert len(policies) == 1 and len(templates) == 1, (
        f"control policy {policies!r} and template {templates!r} by name"
    )
    got_policy = nsm.get_policy(policyIdentifier=policies[0])
    got = (got_policy["status"], got_policy["associatedTemplateAndRuleList"])
    assert got == ("ACTIVE", [{"templateArn": templates[0]}]), f"control policy reads {got!r}"

    delete_stack(cfn, good_id)
    own_id = policies[0].rsplit(":", 1)[-1]
    not_found = ("ResourceNotFoundException", f"Policy not found: {own_id}")
    expect_error(lambda: nsm.get_policy(policyIdentifier=policies[0]), *not_found)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
