"""cloudwatch-insight-rule-cfn-deploy-delete-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cloudwatch-insight-rule-cfn-deploy-delete-lifecycle"
GROUP = "deploy"
SERVICES = ["cloudformation", "cloudwatch"]

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

_RULE_GONE = ("ResourceNotFoundException", "")


def _rule_body(log_group: str) -> str:
    return json.dumps({
        "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
        "LogGroupNames": [log_group],
        "LogFormat": "JSON",
        "Contribution": {"Keys": ["$.clientIp"], "Filters": []},
        "AggregateOn": "Count",
    })


def _template(log_group_name: str, rule_name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "LogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {"LogGroupName": log_group_name},
            },
            "Rule": {
                "Type": "AWS::CloudWatch::InsightRule",
                "Properties": {
                    "RuleName": rule_name,
                    "RuleState": "ENABLED",
                    "RuleBody": _rule_body(log_group_name),
                },
            },
        },
        "Outputs": {
            "RuleRef": {"Value": {"Ref": "Rule"}},
            "RuleArn": {"Value": {"Fn::GetAtt": ["Rule", "Arn"]}},
        },
    })


def _find_rule(cw, rule_name):
    """The rule named ``rule_name``; DescribeInsightRules has no paginator, so every page is read."""
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        page = cw.describe_insight_rules(**kwargs)
        for rule in page.get("InsightRules", []):
            if rule["Name"] == rule_name:
                return rule
        token = page.get("NextToken")
        if not token:
            return None


def _poll_until(fn, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if last:
            return last
        time.sleep(interval_s)
    return last


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed Contributor Insights rule is created ENABLED with its RuleBody,
    Ref and GetAtt Arn resolve to its real ARN, and stack deletion removes it from CloudWatch.
    """
    cf = ctx.client("cloudformation")
    cw = ctx.client("cloudwatch")

    stack_name = ctx.unique_name("sim2real-xsvc-cwirule-")
    log_group_name = ctx.unique_name("sim2real-xsvc-cwirule-lg-")
    rule_name = ctx.unique_name("sim2real-xsvc-cwirule-")
    body = _rule_body(log_group_name)

    stack_gone = ("ValidationError", f"Stack with id {stack_name} does not exist")
    stack_id = create_stack(ctx, cf, stack_name, _template(log_group_name, rule_name))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", f"stack status after create is {status!r}"

    outputs = stack_outputs(cf, stack_id)
    expected_arn = f"arn:{stack_id.split(':')[1]}:cloudwatch:{ctx.region}:{ctx.account}:insight-rule/{rule_name}"
    assert outputs["RuleRef"] == expected_arn, (
        f"Ref on the rule is {outputs['RuleRef']!r}, expected its ARN {expected_arn!r}"
    )
    assert outputs["RuleArn"] == expected_arn, (
        f"GetAtt Arn is {outputs['RuleArn']!r}, expected {expected_arn!r}"
    )

    rule = _poll_until(lambda: _find_rule(cw, rule_name), timeout_s=30)
    assert rule is not None, f"rule {rule_name!r} not visible in DescribeInsightRules after create"
    assert rule["State"] == "ENABLED", f"created rule state is {rule['State']!r}, expected 'ENABLED'"
    assert json.loads(rule["Definition"]) == json.loads(body), (
        f"created rule definition is {rule['Definition']!r}, expected the template's RuleBody"
    )

    tags_resp = cw.list_tags_for_resource(ResourceARN=expected_arn)
    created_tags = {t["Key"]: t["Value"] for t in tags_resp["Tags"]}
    assert created_tags.get("aws:cloudformation:stack-name") == stack_name, (
        f"stack-name system tag is {created_tags.get('aws:cloudformation:stack-name')!r}, "
        f"expected {stack_name!r}"
    )

    # ---- stack delete removes the rule ----
    delete_stack(cf, stack_id)
    expect_error(lambda: cf.describe_stacks(StackName=stack_name), *stack_gone)
    expect_error(lambda: cw.list_tags_for_resource(ResourceARN=expected_arn), *_RULE_GONE)
    assert _find_rule(cw, rule_name) is None, (
        f"rule {rule_name!r} still visible in DescribeInsightRules after stack delete"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
