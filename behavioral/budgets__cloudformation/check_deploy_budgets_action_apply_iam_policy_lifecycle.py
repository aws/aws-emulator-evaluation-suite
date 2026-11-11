"""deploy-budgets-action-apply-iam-policy-lifecycle."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-budgets-action-apply-iam-policy-lifecycle"
GROUP = "deploy"
SERVICES = ["budgets", "cloudformation"]

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


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


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

_ATTEMPTS = 3  # the in-stack execution role can be refused until IAM propagates it
_PROPAGATION = "AccessDenied"  # the action handler's code for a role not yet assumable


def _budget_gone(name):
    return ("NotFoundException", f"Unable to get budget: {name} - the budget doesn't exist.")


def _template(budget_name, with_action=True):
    """Budget, action, both roles, the managed policy and the topic all live in the stack."""
    resources = {
        "Budget": {"Type": "AWS::Budgets::Budget", "Properties": {"Budget": {
            "BudgetName": budget_name,
            "BudgetLimit": {"Amount": "1000000.0", "Unit": "USD"},
            "TimeUnit": "MONTHLY",
            "BudgetType": "COST",
        }}},
        "TargetRole": {"Type": "AWS::IAM::Role", "Properties": {
            "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                "Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole"}]},
        }},
        "AppliedPolicy": {"Type": "AWS::IAM::ManagedPolicy", "Properties": {
            "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
                "Effect": "Allow", "Action": ["s3:ListAllMyBuckets"], "Resource": "*"}]},
        }},
        "ExecutionRole": {"Type": "AWS::IAM::Role", "Properties": {
            "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                "Effect": "Allow", "Principal": {"Service": "budgets.amazonaws.com"},
                "Action": "sts:AssumeRole"}]},
            "Policies": [{"PolicyName": "sim2real-apply-one-policy", "PolicyDocument": {
                "Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow",
                    "Action": ["iam:AttachRolePolicy", "iam:DetachRolePolicy"],
                    "Resource": {"Fn::GetAtt": ["TargetRole", "Arn"]},
                    "Condition": {"ArnEquals": {"iam:PolicyARN": {"Ref": "AppliedPolicy"}}},
                }]}}],
        }},
        "Topic": {"Type": "AWS::SNS::Topic", "Properties": {}},
    }
    outputs = {
        "BudgetRef": {"Value": {"Ref": "Budget"}},
        "TargetRoleName": {"Value": {"Ref": "TargetRole"}},
        "PolicyArn": {"Value": {"Ref": "AppliedPolicy"}},
        "ExecutionRoleArn": {"Value": {"Fn::GetAtt": ["ExecutionRole", "Arn"]}},
        "TopicArn": {"Value": {"Ref": "Topic"}},
    }
    if with_action:
        resources["BudgetsAction"] = {"Type": "AWS::Budgets::BudgetsAction", "Properties": {
            "BudgetName": {"Ref": "Budget"},
            "NotificationType": "ACTUAL",
            "ActionType": "APPLY_IAM_POLICY",
            "ActionThreshold": {"Type": "PERCENTAGE", "Value": 80.0},
            "Definition": {"IamActionDefinition": {"PolicyArn": {"Ref": "AppliedPolicy"},
                                                   "Roles": [{"Ref": "TargetRole"}]}},
            "ExecutionRoleArn": {"Fn::GetAtt": ["ExecutionRole", "Arn"]},
            "ApprovalModel": "MANUAL",
            "Subscribers": [{"Type": "SNS", "Address": {"Ref": "Topic"}}],
        }}
        outputs["ActionId"] = {"Value": {"Fn::GetAtt": ["BudgetsAction", "ActionId"]}}
        outputs["ActionRef"] = {"Value": {"Ref": "BudgetsAction"}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


def _deploy(ctx, cfn):
    """Create the stack; retry under fresh names only on the action's AccessDenied handler code.

    Each attempt's delete is registered by create_stack before any wait.
    """
    for attempt in range(1, _ATTEMPTS + 1):
        budget_name = ctx.unique_name("sim2real-cfnaction-")
        stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfnaction-"),
                                _template(budget_name), Capabilities=["CAPABILITY_IAM"])
        status = wait_stack(cfn, stack_id)
        if status == "CREATE_COMPLETE":
            return stack_id, budget_name
        events = stack_events(cfn, stack_id)
        reason = failed_reason(events, "BudgetsAction")
        if handler_reason(reason, ctx.account, budget_name)[1] != _PROPAGATION or attempt == _ATTEMPTS:
            raise AssertionError(f"stack ended {status!r} on attempt {attempt}: {reason!r}")
        delete_stack(cfn, stack_id)
    raise AssertionError("unreachable")


def _error(fn):
    """The Error of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation BudgetsAction and its budget read back through Budgets, then delete child-first.

    Every templated property matches DescribeBudget and a DescribeBudgetActionsForBudget entry; an
    update dropping the action removes it while the budget stays, and the stack delete the budget.
    """
    cfn = ctx.client("cloudformation")
    budgets = ctx.client("budgets")
    account = ctx.account

    stack_id, budget_name = _deploy(ctx, cfn)
    out = stack_outputs(cfn, stack_id)
    assert out["BudgetRef"] == budget_name, f"Budget Ref {out['BudgetRef']!r} != {budget_name!r}"

    budget = budgets.describe_budget(AccountId=account, BudgetName=budget_name)["Budget"]
    got = (budget["BudgetName"], budget["BudgetLimit"], budget["TimeUnit"], budget["BudgetType"])
    want = (budget_name, {"Amount": "1000000.0", "Unit": "USD"}, "MONTHLY", "COST")
    assert got == want, f"DescribeBudget {got!r}, expected {want!r}"

    # The action from an independent per-budget list: exactly one, its id the ActionId GetAtt.
    actions = paginate(budgets, "describe_budget_actions_for_budget", "Actions",
                       AccountId=account, BudgetName=budget_name)
    assert [a["ActionId"] for a in actions] == [out["ActionId"]], (
        f"DescribeBudgetActionsForBudget {actions!r}; GetAtt ActionId {out['ActionId']!r}"
    )
    action_id = actions[0]["ActionId"]
    assert out["ActionRef"] == f"{action_id}|{budget_name}", (
        f"BudgetsAction Ref {out['ActionRef']!r}, expected {action_id}|{budget_name}"
    )
    described = budgets.describe_budget_action(
        AccountId=account, BudgetName=budget_name, ActionId=action_id)["Action"]
    got = {k: described[k] for k in ("BudgetName", "Status", "ApprovalModel", "ActionType",
                                     "NotificationType", "ActionThreshold", "ExecutionRoleArn",
                                     "Definition", "Subscribers")}
    want = {
        "BudgetName": budget_name, "Status": "STANDBY", "ApprovalModel": "MANUAL",
        "ActionType": "APPLY_IAM_POLICY", "NotificationType": "ACTUAL",
        "ActionThreshold": {"ActionThresholdValue": 80.0, "ActionThresholdType": "PERCENTAGE"},
        "ExecutionRoleArn": out["ExecutionRoleArn"],
        "Definition": {"IamActionDefinition": {"PolicyArn": out["PolicyArn"],
                                               "Roles": [out["TargetRoleName"]]}},
        "Subscribers": [{"SubscriptionType": "SNS", "Address": out["TopicArn"]}],
    }
    assert got == want, f"DescribeBudgetAction {got!r}, expected {want!r}"

    # Child first: the update drops only the action; its own NotFound while the budget answers.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(budget_name, with_action=False),
                     Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"action-dropping update ended {status!r}"
    kept = budgets.describe_budget(AccountId=account, BudgetName=budget_name)["Budget"]
    assert kept["BudgetName"] == budget_name, (
        f"budget after the action-dropping update: {kept['BudgetName']!r}, expected {budget_name!r}"
    )
    err = _error(lambda: budgets.describe_budget_action(
        AccountId=account, BudgetName=budget_name, ActionId=action_id))
    got = (err["Code"], masked(err["Message"], account))
    want = ("NotFoundException", f"Action for [AccountId: <account>, ActionId: {action_id}] is not found!")
    assert got == want, f"DescribeBudgetAction after the update: {got!r}, expected {want!r}"

    delete_stack(cfn, stack_id)
    expect_error(lambda: budgets.describe_budget(AccountId=account, BudgetName=budget_name),
                 *_budget_gone(budget_name))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
