"""deploy-gamelift-matchmaking-ruleset-and-configuration-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-gamelift-matchmaking-ruleset-and-configuration-round-trip-and-delete"
GROUP = "cloudformation"
SERVICES = ["cloudformation", "gamelift"]

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

_RULE_SET_BODY = {
    "name": "sim2real-ruleset",
    "ruleLanguageVersion": "1.0",
    "teams": [{"name": "alpha", "minPlayers": 1, "maxPlayers": 4}],
}
_REQUEST_TIMEOUT_SECONDS = 15


def _template(ruleset_name: str, config_name: str, with_config: bool = True) -> str:
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "RuleSet": {
                "Type": "AWS::GameLift::MatchmakingRuleSet",
                "Properties": {"Name": ruleset_name, "RuleSetBody": json.dumps(_RULE_SET_BODY)},
            },
            "Config": {
                "Type": "AWS::GameLift::MatchmakingConfiguration",
                "Properties": {
                    "Name": config_name,
                    "AcceptanceRequired": False,
                    "RequestTimeoutSeconds": _REQUEST_TIMEOUT_SECONDS,
                    "RuleSetName": {"Ref": "RuleSet"},
                    "FlexMatchMode": "STANDALONE",
                },
                "DependsOn": "RuleSet",
            },
        },
        "Outputs": {
            "RuleSetName": {"Value": {"Ref": "RuleSet"}},
            "RuleSetArn": {"Value": {"Fn::GetAtt": ["RuleSet", "Arn"]}},
            "ConfigName": {"Value": {"Ref": "Config"}},
            "ConfigArn": {"Value": {"Fn::GetAtt": ["Config", "Arn"]}},
        },
    }
    if not with_config:
        del template["Resources"]["Config"]
        del template["Outputs"]["ConfigName"], template["Outputs"]["ConfigArn"]
    return json.dumps(template)


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation MatchmakingRuleSet and dependent STANDALONE MatchmakingConfiguration read
    back through GameLift with the template's fields; an update dropping the configuration removes
    it while the rule set stays, and deleting the stack removes the rule set.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-gamelift-matchmakingconfiguration.html
    """
    gl = ctx.client("gamelift")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-glmm-")
    ruleset_name = ctx.unique_name("sim2real-glmm-rs-")
    config_name = ctx.unique_name("sim2real-glmm-cfg-")

    stack_id = create_stack(ctx, cfn, stack, _template(ruleset_name, config_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE: "
        f"{decisive_rows(stack_events(cfn, stack_id))!r}"
    )

    outputs = stack_outputs(cfn, stack_id)
    ruleset_ref, ruleset_arn = outputs["RuleSetName"], outputs["RuleSetArn"]
    config_ref, config_arn = outputs["ConfigName"], outputs["ConfigArn"]
    assert ruleset_ref == ruleset_name, f"Ref output {ruleset_ref!r} != declared Name {ruleset_name!r}"
    assert config_ref == config_name, f"Ref output {config_ref!r} != declared Name {config_name!r}"

    rulesets = gl.describe_matchmaking_rule_sets(Names=[ruleset_name])["RuleSets"]
    assert len(rulesets) == 1, f"expected one rule set named {ruleset_name!r}, got {rulesets!r}"
    ruleset = rulesets[0]
    assert ruleset["RuleSetName"] == ruleset_name, (
        f"expected RuleSetName {ruleset_name!r}, GameLift reports {ruleset['RuleSetName']!r}"
    )
    assert ruleset["RuleSetArn"] == ruleset_arn, (
        f"expected RuleSetArn {ruleset_arn!r}, GameLift reports {ruleset['RuleSetArn']!r}"
    )
    assert json.loads(ruleset["RuleSetBody"]) == _RULE_SET_BODY, (
        f"expected RuleSetBody {_RULE_SET_BODY!r}, GameLift reports {ruleset['RuleSetBody']!r}"
    )

    configs = gl.describe_matchmaking_configurations(Names=[config_name])["Configurations"]
    assert len(configs) == 1, f"expected one configuration named {config_name!r}, got {configs!r}"
    config = configs[0]
    assert config["Name"] == config_name, (
        f"expected Name {config_name!r}, GameLift reports {config['Name']!r}"
    )
    assert config["ConfigurationArn"] == config_arn, (
        f"expected ConfigurationArn {config_arn!r}, GameLift reports {config['ConfigurationArn']!r}"
    )
    assert config["AcceptanceRequired"] is False, (
        f"expected AcceptanceRequired False, GameLift reports {config['AcceptanceRequired']!r}"
    )
    assert config["RequestTimeoutSeconds"] == _REQUEST_TIMEOUT_SECONDS, (
        f"expected RequestTimeoutSeconds {_REQUEST_TIMEOUT_SECONDS}, "
        f"GameLift reports {config['RequestTimeoutSeconds']!r}"
    )
    assert config["RuleSetName"] == ruleset_name, (
        f"expected RuleSetName {ruleset_name!r}, GameLift reports {config['RuleSetName']!r}"
    )
    assert config["FlexMatchMode"] == "STANDALONE", (
        f"expected FlexMatchMode STANDALONE, GameLift reports {config['FlexMatchMode']!r}"
    )

    # Child first: an update dropping only the configuration removes it while the rule set,
    # the same one (RuleSetArn and CreationTime), still answers.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(ruleset_name, config_name,
                                                               with_config=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"configuration-removing update ended {status!r}"
    config_gone = ("InvalidRequestException", f"Configuration not found: {config_name}")
    expect_error(lambda: gl.describe_matchmaking_configurations(Names=[config_name]),
                 *config_gone)
    still = gl.describe_matchmaking_rule_sets(Names=[ruleset_name])["RuleSets"]
    assert [(r["RuleSetArn"], r["CreationTime"]) for r in still] == [
        (ruleset["RuleSetArn"], ruleset["CreationTime"])
    ], f"after dropping the configuration the rule set reads {still!r}"

    delete_stack(cfn, stack_id)
    ruleset_gone = ("InvalidRequestException", f"Failed to find rule set: {ruleset_name}")
    expect_error(lambda: gl.describe_matchmaking_rule_sets(Names=[ruleset_name]), *ruleset_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
