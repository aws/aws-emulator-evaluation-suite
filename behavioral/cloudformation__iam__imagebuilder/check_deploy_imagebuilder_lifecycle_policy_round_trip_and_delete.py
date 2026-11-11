"""deploy-imagebuilder-lifecycle-policy-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-imagebuilder-lifecycle-policy-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam", "imagebuilder"]

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

_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "imagebuilder.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}
_EXECUTION_POLICY = "service-role/EC2ImageBuilderLifecycleExecutionPolicy"
_SELECTION_KEY = "sim2real-selection"


def _template(role_name, policy_name):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name, "AssumeRolePolicyDocument": _TRUST_POLICY,
                    "ManagedPolicyArns": [
                        {"Fn::Sub": f"arn:${{AWS::Partition}}:iam::aws:policy/{_EXECUTION_POLICY}"},
                    ],
                    "Tags": [{"Key": "sim2real-ib", "Value": policy_name}],
                },
            },
            "Policy": {
                "Type": "AWS::ImageBuilder::LifecyclePolicy",
                "Properties": {
                    "Name": policy_name,
                    "Description": "sim2real lifecycle policy",
                    "ExecutionRole": {"Fn::GetAtt": ["Role", "Arn"]},
                    "ResourceType": "AMI_IMAGE",
                    "Status": "DISABLED",
                    "PolicyDetails": [{
                        "Action": {"Type": "DELETE"},
                        "Filter": {"Type": "AGE", "Value": 365, "Unit": "DAYS"},
                    }],
                    "ResourceSelection": {"TagMap": {_SELECTION_KEY: policy_name}},
                    "Tags": {"sim2real-ib": policy_name},
                },
            },
        },
        "Outputs": {
            "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
            "PolicyArn": {"Value": {"Ref": "Policy"}},
            "PolicyGetAttArn": {"Value": {"Fn::GetAtt": ["Policy", "Arn"]}},
        },
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Image Builder LifecyclePolicy reads back through Image Builder and IAM.

    Ref is the ARN Image Builder lists under the declared name; the execution role, rules,
    selection, status and tags read back, and deleting the stack removes the policy and its role.
    """
    iam = ctx.client("iam")
    ib = ctx.client("imagebuilder")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-iblcp-")
    role_name = ctx.unique_name("sim2real-iblcp-role-")
    policy_name = ctx.unique_name("sim2real-iblcp-res-")

    stack_id = create_stack(ctx, cfn, stack, _template(role_name, policy_name),
                            Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    partition = stack_id.split(":")[1]
    out = stack_outputs(cfn, stack_id)
    arn = f"arn:{partition}:imagebuilder:{ctx.region}:{ctx.account}:lifecycle-policy/{policy_name}"

    # Ref against an independent read: the list entry under the declared name.
    listed = [p["arn"] for p in paginate(ib, "list_lifecycle_policies",
                                         "lifecyclePolicySummaryList",
                                         filters=[{"name": "name", "values": [policy_name]}])]
    assert listed == [out["PolicyArn"]], f"listed {listed!r} for Ref {out['PolicyArn']!r}"
    assert (out["PolicyArn"], out["PolicyGetAttArn"]) == (arn, arn), f"Ref / GetAtt Arn {out!r}"

    role = iam.get_role(RoleName=role_name)["Role"]
    assert (out["RoleArn"], role["AssumeRolePolicyDocument"]) == (role["Arn"], _TRUST_POLICY), (
        f"GetAtt Role.Arn {out['RoleArn']!r}, IAM role {role!r}"
    )
    attached = [p["PolicyArn"] for p in paginate(iam, "list_attached_role_policies",
                                                 "AttachedPolicies", RoleName=role_name)]
    assert attached == [f"arn:{partition}:iam::aws:policy/{_EXECUTION_POLICY}"], (
        f"role managed policies {attached!r}"
    )

    got = ib.get_lifecycle_policy(lifecyclePolicyArn=listed[0])["lifecyclePolicy"]
    assert (got["name"], got.get("description"), got["status"], got["resourceType"],
            got["executionRole"]) == (policy_name, "sim2real lifecycle policy", "DISABLED",
                                      "AMI_IMAGE", role["Arn"]), f"lifecycle policy {got!r}"
    assert got["policyDetails"] == [{
        "action": {"type": "DELETE"}, "filter": {"type": "AGE", "value": 365, "unit": "DAYS"},
    }], f"policyDetails {got['policyDetails']!r}"
    assert got["resourceSelection"] == {"tagMap": {_SELECTION_KEY: policy_name}}, (
        f"resourceSelection {got['resourceSelection']!r}"
    )
    own_tags = {k: v for k, v in got.get("tags", {}).items() if k.startswith("sim2real-")}
    assert own_tags == {"sim2real-ib": policy_name}, f"policy tags {got.get('tags')!r}"

    delete_stack(cfn, stack_id)
    policy_gone = ("ResourceNotFoundException",
                   f"The following required resource 'LifecyclePolicy' cannot be found: '{arn}'.")
    expect_error(lambda: ib.get_lifecycle_policy(lifecyclePolicyArn=arn), *policy_gone)
    role_gone = ("NoSuchEntity", f"The role with name {role_name} cannot be found.")
    until_raises(lambda: iam.get_role(RoleName=role_name))
    expect_error(lambda: iam.get_role(RoleName=role_name), *role_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
