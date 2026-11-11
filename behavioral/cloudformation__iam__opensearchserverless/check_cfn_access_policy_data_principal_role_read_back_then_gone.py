"""cfn-access-policy-data-principal-role-read-back-then-gone."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-access-policy-data-principal-role-read-back-then-gone"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam", "opensearchserverless"]

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

_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}


def _short_name(ctx, prefix):
    """A unique lowercase name OpenSearchServerless accepts (3-32 of [a-z0-9-])."""
    raw = re.sub(r"[^a-z0-9-]", "", ctx.unique_name(prefix + "-").lower())
    return raw[:32].rstrip("-")


def _rules(prefix):
    return [{
        "ResourceType": "collection",
        "Resource": [f"collection/{prefix}*"],
        "Permission": ["aoss:CreateCollectionItems", "aoss:DescribeCollectionItems"],
    }]


def _template(role_name, policy_name, prefix, principal=None):
    """A role and a data AccessPolicy granting ``principal`` (default: the role's own ARN)."""
    policy = json.dumps([{"Rules": _rules(prefix), "Principal": [principal or "__ROLE_ARN__"]}])
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name, "AssumeRolePolicyDocument": _TRUST,
                    "Tags": [{"Key": "sim2real-aoss", "Value": policy_name}],
                },
            },
            "AccessPolicy": {
                "Type": "AWS::OpenSearchServerless::AccessPolicy",
                "DependsOn": "Role",
                "Properties": {
                    "Name": policy_name,
                    "Type": "data",
                    "Policy": {"Fn::Sub": policy.replace("__ROLE_ARN__", "${Role.Arn}")},
                },
            },
        },
        "Outputs": {
            "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
            "PolicyRef": {"Value": {"Ref": "AccessPolicy"}},
        },
    })


def _listed(aoss, name):
    """``(name, type)`` of every data access policy listed under exactly ``name``."""
    items, token = [], None
    while True:
        page = aoss.list_access_policies(type="data", **({"nextToken": token} if token else {}))
        items += [(p["name"], p["type"]) for p in page["accessPolicySummaries"]
                  if p["name"] == name]
        token = page.get("nextToken")
        if not token:
            return items


@tags("axis:happy-path", "cap:c7", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation OpenSearchServerless data AccessPolicy reads back with its role principal.

    Ref is Type|Name of the policy listed under the declared name; the rules and role principal
    read back, and deleting the stack removes the policy and the role.
    """
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    aoss = ctx.client("opensearchserverless")
    stack = ctx.unique_name("sim2real-cfn-apol-")
    role_name = ctx.unique_name("sim2real-cfn-apol-role-")
    policy_name = _short_name(ctx, "sim2real-apol")
    prefix = _short_name(ctx, "sim2real-apolcoll")

    stack_id = create_stack(ctx, cfn, stack, _template(role_name, policy_name, prefix),
                            Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    listed = _listed(aoss, policy_name)
    assert listed == [(policy_name, "data")], f"ListAccessPolicies {listed!r}"
    assert out["PolicyRef"] == f"data|{listed[0][0]}", f"Ref {out['PolicyRef']!r}"

    role = iam.get_role(RoleName=role_name)["Role"]
    role_tags = {t["Key"]: t["Value"] for t in role.get("Tags", [])}
    assert (out["RoleArn"], role["AssumeRolePolicyDocument"], role_tags.get("sim2real-aoss")) == (
        role["Arn"], _TRUST, policy_name), f"GetAtt Role.Arn {out['RoleArn']!r}, role {role!r}"
    detail = aoss.get_access_policy(name=policy_name, type="data")["accessPolicyDetail"]
    got = (detail["name"], detail["type"], detail["policy"])
    want = (policy_name, "data", [{"Rules": _rules(prefix), "Principal": [role["Arn"]]}])
    assert got == want, f"access policy (name, type, policy) {got!r}"

    delete_stack(cfn, stack_id)
    until_raises(lambda: aoss.get_access_policy(name=policy_name, type="data"))
    gone = ("ResourceNotFoundException", f"Policy with name {policy_name} and type data is not found")
    expect_error(lambda: aoss.get_access_policy(name=policy_name, type="data"), *gone)
    role_gone = ("NoSuchEntity", f"The role with name {role_name} cannot be found.")
    until_raises(lambda: iam.get_role(RoleName=role_name))
    expect_error(lambda: iam.get_role(RoleName=role_name), *role_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
