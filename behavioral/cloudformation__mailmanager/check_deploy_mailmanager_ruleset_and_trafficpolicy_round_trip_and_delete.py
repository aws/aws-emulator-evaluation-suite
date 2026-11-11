"""deploy-mailmanager-ruleset-and-trafficpolicy-round-trip-and-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-mailmanager-ruleset-and-trafficpolicy-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "mailmanager"]

# ---- CloudFormation helpers: copy VERBATIM; delete the ones the check never calls. ----

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

_TEMPLATE_BODY = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  RuleSetNameParam:
    Type: String
  TrafficPolicyNameParam:
    Type: String
Resources:
  RuleSet:
    Type: AWS::SES::MailManagerRuleSet
    Properties:
      RuleSetName: !Ref RuleSetNameParam
      Rules:
        - Name: drop-all
          Actions:
            - Drop: {}
  TrafficPolicy:
    Type: AWS::SES::MailManagerTrafficPolicy
    Properties:
      TrafficPolicyName: !Ref TrafficPolicyNameParam
      DefaultAction: DENY
      PolicyStatements:
        - Action: DENY
          Conditions:
            - IpExpression:
                Evaluate:
                  Attribute: SENDER_IP
                Operator: CIDR_MATCHES
                Values:
                  - 0.0.0.0/0
Outputs:
  RuleSetIdOut:
    Value: !Ref RuleSet
  RuleSetArnOut:
    Value: !GetAtt RuleSet.RuleSetArn
  TrafficPolicyIdOut:
    Value: !Ref TrafficPolicy
  TrafficPolicyArnOut:
    Value: !GetAtt TrafficPolicy.TrafficPolicyArn
"""


def _listed(mm, op: str, key: str, name_field: str, name: str) -> list[dict]:
    """Every entry a paginated MailManager List call returns under ``name``."""
    return [item for item in paginate(mm, op, key) if item[name_field] == name]


def _user_tags(mm, arn: str) -> dict:
    tag_list = mm.list_tags_for_resource(ResourceArn=arn)["Tags"]
    return {t["Key"]: t["Value"] for t in tag_list if not t["Key"].startswith("aws:")}


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation MailManagerRuleSet and MailManagerTrafficPolicy read back from MailManager
    with the template's rules, policy and tags, and both are NotFound after the stack delete.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ses-mailmanagerruleset.html
    """
    cfn = ctx.client("cloudformation")
    mm = ctx.client("mailmanager")

    stack_name = ctx.unique_name("sim2real-cfn-mm-")
    rule_set_name = ctx.unique_name("sim2real-cfn-mm-rs-")
    traffic_policy_name = ctx.unique_name("sim2real-cfn-mm-tp-")

    stack_id = create_stack(
        ctx, cfn, stack_name, _TEMPLATE_BODY,
        Parameters=[
            {"ParameterKey": "RuleSetNameParam", "ParameterValue": rule_set_name},
            {"ParameterKey": "TrafficPolicyNameParam", "ParameterValue": traffic_policy_name},
        ],
    )
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack create ended in {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    rule_set_id = outputs["RuleSetIdOut"]
    traffic_policy_id = outputs["TrafficPolicyIdOut"]

    listed = [e["RuleSetId"] for e in _listed(mm, "list_rule_sets", "RuleSets", "RuleSetName", rule_set_name)]
    assert listed == [rule_set_id], (
        f"ListRuleSets ids under {rule_set_name!r} were {listed!r}, expected [Ref {rule_set_id!r}]"
    )
    rule_set = mm.get_rule_set(RuleSetId=rule_set_id)
    assert rule_set["RuleSetName"] == rule_set_name, (
        f"expected name {rule_set_name!r}, got {rule_set['RuleSetName']!r}"
    )
    assert rule_set["RuleSetArn"] == outputs["RuleSetArnOut"], (
        f"GetRuleSet arn {rule_set['RuleSetArn']!r} != stack GetAtt {outputs['RuleSetArnOut']!r}"
    )
    assert rule_set["Rules"] == [{"Name": "drop-all", "Actions": [{"Drop": {}}]}], (
        f"expected a single drop-all rule, got {rule_set['Rules']!r}"
    )

    listed = [
        e["TrafficPolicyId"]
        for e in _listed(mm, "list_traffic_policies", "TrafficPolicies", "TrafficPolicyName", traffic_policy_name)
    ]
    assert listed == [traffic_policy_id], (
        f"ListTrafficPolicies ids under {traffic_policy_name!r} were {listed!r}, "
        f"expected [Ref {traffic_policy_id!r}]"
    )
    traffic_policy = mm.get_traffic_policy(TrafficPolicyId=traffic_policy_id)
    assert traffic_policy["TrafficPolicyName"] == traffic_policy_name, (
        f"expected name {traffic_policy_name!r}, got {traffic_policy['TrafficPolicyName']!r}"
    )
    assert traffic_policy["TrafficPolicyArn"] == outputs["TrafficPolicyArnOut"], (
        f"GetTrafficPolicy arn {traffic_policy['TrafficPolicyArn']!r} != "
        f"stack GetAtt {outputs['TrafficPolicyArnOut']!r}"
    )
    assert traffic_policy["DefaultAction"] == "DENY", (
        f"expected DefaultAction DENY, got {traffic_policy['DefaultAction']!r}"
    )
    assert traffic_policy["PolicyStatements"] == [
        {
            "Conditions": [
                {
                    "IpExpression": {
                        "Evaluate": {"Attribute": "SENDER_IP"},
                        "Operator": "CIDR_MATCHES",
                        "Values": ["0.0.0.0/0"],
                    }
                }
            ],
            "Action": "DENY",
        }
    ], f"unexpected PolicyStatements {traffic_policy['PolicyStatements']!r}"

    for label, arn in (("rule set", rule_set["RuleSetArn"]), ("traffic policy", traffic_policy["TrafficPolicyArn"])):
        found = _user_tags(mm, arn)
        assert found == {"sim2real": stack_name}, (
            f"the {label}'s tags (aws: keys dropped) were {found!r}, expected the stack's propagated tag"
        )

    delete_stack(cfn, stack_id)

    rule_set_gone = ("ResourceNotFoundException", f"Rule set does not exist: {rule_set_id}")
    expect_error(lambda: mm.get_rule_set(RuleSetId=rule_set_id), *rule_set_gone)
    policy_gone = ("ResourceNotFoundException", f"TrafficPolicy <{traffic_policy_id}> does not exist")
    expect_error(lambda: mm.get_traffic_policy(TrafficPolicyId=traffic_policy_id), *policy_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
