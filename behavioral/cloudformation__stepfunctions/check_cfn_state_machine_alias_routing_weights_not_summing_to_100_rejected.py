"""cfn-state-machine-alias-routing-weights-not-summing-to-100-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "cfn-state-machine-alias-routing-weights-not-summing-to-100-rejected"
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


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


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


# ---- Check-specific: the template, then run(). ----

_DEFINITION = {"StartAt": "S", "States": {"S": {"Type": "Pass", "End": True}}}
_REJECTED = (
    "Sum of routing configuration weights must equal 100. Received: [60] (Service: Sfn, "
    "Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)


def _base_template(sm_name: str, role_name: str) -> str:
    """The state machine and its published version the alias stacks route to."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
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
                    "RoleArn": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "DefinitionString": json.dumps(_DEFINITION),
                },
            },
            "MyVersion": {
                "Type": "AWS::StepFunctions::StateMachineVersion",
                "Properties": {"StateMachineArn": {"Ref": "MyStateMachine"}},
            },
        },
        "Outputs": {
            "StateMachineArn": {"Value": {"Ref": "MyStateMachine"}},
            "VersionArn": {"Value": {"Ref": "MyVersion"}},
        },
    })


def _alias_template(alias_name: str, version_arn: str, weight: int) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "MyAlias": {
                "Type": "AWS::StepFunctions::StateMachineAlias",
                "Properties": {
                    "Name": alias_name,
                    "RoutingConfiguration": [
                        {"StateMachineVersionArn": version_arn, "Weight": weight}
                    ],
                },
            },
        },
        "Outputs": {"AliasArnRef": {"Value": {"Ref": "MyAlias"}}},
    })


def _aliases(sfn, sm_arn):
    """Every alias of ``sm_arn`` across nextToken pages (the operation has no paginator)."""
    out, kw = [], {"stateMachineArn": sm_arn}
    while True:
        page = sfn.list_state_machine_aliases(**kw)
        out += page.get("stateMachineAliases", [])
        if not page.get("nextToken"):
            return out
        kw["nextToken"] = page["nextToken"]


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CFN AWS::StepFunctions::StateMachineAlias whose routing weights do not sum to 100 is
    rejected with Step Functions' own validation message and the state machine holds no alias,
    while the same alias template with weight 100 deploys and routes to the version."""
    cfn, sfn = ctx.client("cloudformation"), ctx.client("stepfunctions")
    alias_name = ctx.unique_name("sim2real-behav-sfnalias-")

    base_id = create_stack(
        ctx, cfn, ctx.unique_name("sim2real-behav-sfnaliasbase-"),
        _base_template(ctx.unique_name("sim2real-behav-sfnaliassm-"),
                       ctx.unique_name("sim2real-behav-sfnaliasrole-")),
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    status = wait_stack(cfn, base_id)
    assert status == "CREATE_COMPLETE", (
        f"base stack ended {status!r}: {decisive_rows(stack_events(cfn, base_id))!r}"
    )
    base = stack_outputs(cfn, base_id)
    sm_arn, version_arn = base["StateMachineArn"], base["VersionArn"]

    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-sfnaliasbad-"),
                          _alias_template(alias_name, version_arn, 60))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected alias stack ended {status!r}"
    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "MyAlias"), ctx.account,
                         alias_name)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"
    listed = _aliases(sfn, sm_arn)
    assert listed == [], f"aliases of the state machine after the rollback: {listed!r}"
    delete_stack(cfn, bad_id)

    # Positive control: the same alias template with weight 100.
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-sfnaliasgood-"),
                           _alias_template(alias_name, version_arn, 100))
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", f"control alias stack ended {status!r}"
    alias_arn = stack_outputs(cfn, good_id)["AliasArnRef"]
    listed = [(a["stateMachineAliasArn"]) for a in _aliases(sfn, sm_arn)]
    assert listed == [alias_arn], f"ListStateMachineAliases {listed!r} for Ref {alias_arn!r}"
    desc = sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn)
    got = (desc["name"], desc["routingConfiguration"])
    want = (alias_name, [{"stateMachineVersionArn": version_arn, "weight": 100}])
    assert got == want, f"control alias (name, routing) {got!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
