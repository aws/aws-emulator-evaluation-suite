"""cfn-state-machine-version-and-alias-round-trip-and-removed-on-stack-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-state-machine-version-and-alias-round-trip-and-removed-on-stack-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "stepfunctions"]

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


def until_raises(fn, timeout_s=90.0):
    """Poll ``fn()`` every 2 s until it raises a ClientError (an eventually consistent delete).

    Grade the error afterwards with expect_error; a success past the deadline fails.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {timeout_s:.0f}s: {result!r}")
        time.sleep(2)


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

_DEFINITION = {"StartAt": "S", "States": {"S": {"Type": "Pass", "Result": {"ok": True}, "End": True}}}


def _template(sm_name, role_name, alias_name, version_desc, alias_desc, children=True):
    resources = {
        "ExecRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": role_name,
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Service": "states.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }],
                },
            },
        },
        "MyStateMachine": {
            "Type": "AWS::StepFunctions::StateMachine",
            "Properties": {
                "StateMachineName": sm_name,
                "StateMachineType": "STANDARD",
                "RoleArn": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                "DefinitionString": json.dumps(_DEFINITION),
            },
        },
    }
    outputs = {"StateMachineArn": {"Value": {"Ref": "MyStateMachine"}}}
    if children:
        resources["MyVersion"] = {
            "Type": "AWS::StepFunctions::StateMachineVersion",
            "Properties": {"StateMachineArn": {"Ref": "MyStateMachine"},
                           "Description": version_desc},
        }
        resources["MyAlias"] = {
            "Type": "AWS::StepFunctions::StateMachineAlias",
            "Properties": {
                "Name": alias_name,
                "Description": alias_desc,
                "RoutingConfiguration": [
                    {"StateMachineVersionArn": {"Ref": "MyVersion"}, "Weight": 100}
                ],
            },
        }
        outputs.update({
            "VersionArnRef": {"Value": {"Ref": "MyVersion"}},
            "VersionArnGetAtt": {"Value": {"Fn::GetAtt": ["MyVersion", "Arn"]}},
            "AliasArnRef": {"Value": {"Ref": "MyAlias"}},
            "AliasArnGetAtt": {"Value": {"Fn::GetAtt": ["MyAlias", "Arn"]}},
        })
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


def _pages(fn, key, **kw):
    """Every ``key`` item across nextToken pages of a list call without a paginator."""
    out = []
    while True:
        page = fn(**kw)
        out += page.get(key, [])
        if not page.get("nextToken"):
            return out
        kw = {**kw, "nextToken": page["nextToken"]}


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed AWS::StepFunctions::StateMachineVersion and ::StateMachineAlias describe with
    the template's values, each Ref and GetAtt Arn is the ARN Step Functions lists, an update
    dropping both removes each while the state machine stays, and the stack delete removes it."""
    cfn, sfn = ctx.client("cloudformation"), ctx.client("stepfunctions")
    sm_name = ctx.unique_name("sim2real-behav-sfnversm-")
    names = (sm_name, ctx.unique_name("sim2real-behav-sfnverrole-"),
             ctx.unique_name("sim2real-behav-sfnveralias-"),
             ctx.unique_name("sim2real-behav-verdesc-"),
             ctx.unique_name("sim2real-behav-aliasdesc-"))
    _, _, alias_name, version_desc, alias_desc = names

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-sfnverstack-"),
                            _template(*names), Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    sm_arn = outputs["StateMachineArn"]
    version_arn, alias_arn = outputs["VersionArnRef"], outputs["AliasArnRef"]

    # Each Ref against an independent list of the state machine's versions and aliases.
    listed = [v["stateMachineVersionArn"] for v in _pages(
        sfn.list_state_machine_versions, "stateMachineVersions", stateMachineArn=sm_arn)]
    got = (listed, outputs["VersionArnGetAtt"])
    assert got == ([version_arn], version_arn), (
        f"(ListStateMachineVersions, GetAtt Arn) {got!r} for Ref {version_arn!r}"
    )
    listed = [a["stateMachineAliasArn"] for a in _pages(
        sfn.list_state_machine_aliases, "stateMachineAliases", stateMachineArn=sm_arn)]
    got = (listed, outputs["AliasArnGetAtt"])
    assert got == ([alias_arn], alias_arn), (
        f"(ListStateMachineAliases, GetAtt Arn) {got!r} for Ref {alias_arn!r}"
    )
    assert alias_arn == f"{sm_arn}:{alias_name}", f"alias ARN {alias_arn!r} for {alias_name!r}"

    desc_v = sfn.describe_state_machine(stateMachineArn=version_arn)
    got = (desc_v["name"], desc_v.get("description"), json.loads(desc_v["definition"]))
    assert got == (sm_name, version_desc, _DEFINITION), f"version reads {got!r}"
    desc_a = sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn)
    got = (desc_a["name"], desc_a.get("description"), desc_a["routingConfiguration"])
    want = (alias_name, alias_desc, [{"stateMachineVersionArn": version_arn, "weight": 100}])
    assert got == want, f"alias reads {got!r}, expected {want!r}"

    # Children first: the update drops the alias and the version while the state machine stays.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(*names, children=False),
                     Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"child-dropping update ended {status!r}"
    until_raises(lambda: sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn),
                 timeout_s=120.0)
    gone = ("ResourceNotFound", f"Resource not found: '{alias_arn}'")
    expect_error(lambda: sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn), *gone)
    until_raises(lambda: sfn.describe_state_machine(stateMachineArn=version_arn), timeout_s=120.0)
    gone = ("StateMachineDoesNotExist", f"State Machine Version Does Not Exist: '{version_arn}'")
    expect_error(lambda: sfn.describe_state_machine(stateMachineArn=version_arn), *gone)
    still = sfn.describe_state_machine(stateMachineArn=sm_arn)
    assert (still["name"], still["status"]) == (sm_name, "ACTIVE"), (
        f"state machine after the update reads {(still['name'], still['status'])!r}"
    )

    delete_stack(cfn, stack_id)
    until_raises(lambda: sfn.describe_state_machine(stateMachineArn=sm_arn), timeout_s=120.0)
    gone = ("StateMachineDoesNotExist", f"State Machine Does Not Exist: '{sm_arn}'")
    expect_error(lambda: sfn.describe_state_machine(stateMachineArn=sm_arn), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
