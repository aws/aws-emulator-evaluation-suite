"""deploy-policyengine-and-policy-round-trip-then-child-and-stack-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-policyengine-and-policy-round-trip-then-child-and-stack-delete"
GROUP = "deploy"
SERVICES = ["bedrock-agentcore-control", "cloudformation"]

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

_CEDAR_STATEMENT = (
    'permit(principal == AgentCore::IamEntity::"${RoleArn}", action, '
    "resource is AgentCore::Gateway);"
)


def _template(role_name, pe_name, policy_name, enforcement_mode="LOG_ONLY"):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                },
            },
            "PolicyEngine": {
                "Type": "AWS::BedrockAgentCore::PolicyEngine",
                "Properties": {
                    "Name": pe_name,
                    "Tags": [{"Key": "sim2real-pe", "Value": pe_name}],
                },
            },
            "Policy": {
                "Type": "AWS::BedrockAgentCore::Policy",
                "Properties": {
                    "PolicyEngineId": {"Fn::GetAtt": ["PolicyEngine", "PolicyEngineId"]},
                    "Name": policy_name,
                    "EnforcementMode": enforcement_mode,
                    "Definition": {
                        "Cedar": {
                            "Statement": {
                                "Fn::Sub": [_CEDAR_STATEMENT,
                                           {"RoleArn": {"Fn::GetAtt": ["Role", "Arn"]}}],
                            },
                        },
                    },
                },
            },
        },
        "Outputs": {
            "PolicyEngineRef": {"Value": {"Ref": "PolicyEngine"}},
            "PolicyEngineId": {"Value": {"Fn::GetAtt": ["PolicyEngine", "PolicyEngineId"]}},
            "PolicyEngineArn": {"Value": {"Fn::GetAtt": ["PolicyEngine", "PolicyEngineArn"]}},
            "PolicyRef": {"Value": {"Ref": "Policy"}},
            "PolicyId": {"Value": {"Fn::GetAtt": ["Policy", "PolicyId"]}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
        },
    })


def _template_without_policy(role_name, pe_name):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                },
            },
            "PolicyEngine": {
                "Type": "AWS::BedrockAgentCore::PolicyEngine",
                "Properties": {
                    "Name": pe_name,
                    "Tags": [{"Key": "sim2real-pe", "Value": pe_name}],
                },
            },
        },
        "Outputs": {
            "PolicyEngineId": {"Value": {"Fn::GetAtt": ["PolicyEngine", "PolicyEngineId"]}},
        },
    })


def _alnum_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    return "".join(ch for ch in raw if ch.isalnum() or ch == "_")


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation PolicyEngine and Policy read back through bedrock-agentcore-control.

    Ref, GetAtt and every templated property match an independent list/get; removing the Policy
    via a stack update deletes only it, and deleting the stack removes the PolicyEngine too.
    """
    cf = ctx.client("cloudformation")
    control = ctx.client("bedrock-agentcore-control")

    role_name = ctx.unique_name("sim2real-polengrole-")
    pe_name = _alnum_name(ctx, "sim2realPolEng")
    policy_name = _alnum_name(ctx, "sim2realPolicy")
    stack = ctx.unique_name("sim2real-polengpolicy-")

    stack_id = create_stack(ctx, cf, stack, _template(role_name, pe_name, policy_name),
                            Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)

    # Ref against an independent read (ListPolicyEngines by the declared name), never read by Ref.
    listed_pe = [p for p in paginate(control, "list_policy_engines", "policyEngines")
                if p["name"] == pe_name]
    assert len(listed_pe) == 1, f"ListPolicyEngines found {listed_pe!r} for name {pe_name!r}"
    assert out["PolicyEngineRef"] == listed_pe[0]["policyEngineArn"], (
        f"Ref {out['PolicyEngineRef']!r} != ListPolicyEngines arn {listed_pe[0]['policyEngineArn']!r}"
    )
    pe = control.get_policy_engine(policyEngineId=out["PolicyEngineId"])
    assert out["PolicyEngineArn"] == pe["policyEngineArn"] == listed_pe[0]["policyEngineArn"], (
        f"GetAtt PolicyEngineArn {out['PolicyEngineArn']!r} != GetPolicyEngine {pe['policyEngineArn']!r}"
    )
    assert pe["name"] == pe_name, f"GetPolicyEngine name {pe['name']!r} != {pe_name!r}"
    pe_tags = control.list_tags_for_resource(resourceArn=pe["policyEngineArn"]).get("tags", {})
    assert pe_tags == {"sim2real": stack, "sim2real-pe": pe_name}, f"PolicyEngine tags {pe_tags!r}"

    # Ref/GetAtt of the Policy against an independent ListPolicies read.
    listed_pol = [p for p in paginate(control, "list_policies", "policies",
                                      policyEngineId=out["PolicyEngineId"])
                 if p["name"] == policy_name]
    assert len(listed_pol) == 1, f"ListPolicies found {listed_pol!r} for name {policy_name!r}"
    assert out["PolicyRef"] == listed_pol[0]["policyArn"], (
        f"Ref {out['PolicyRef']!r} != ListPolicies arn {listed_pol[0]['policyArn']!r}"
    )
    policy = control.get_policy(policyEngineId=out["PolicyEngineId"], policyId=out["PolicyId"])
    assert out["PolicyId"] == policy["policyId"] == listed_pol[0]["policyId"], (
        f"GetAtt PolicyId {out['PolicyId']!r} != GetPolicy {policy['policyId']!r}"
    )
    assert policy["enforcementMode"] == "LOG_ONLY", f"enforcementMode {policy['enforcementMode']!r}"
    want_statement = _CEDAR_STATEMENT.replace("${RoleArn}", out["RoleArn"])
    assert policy["definition"]["cedar"]["statement"] == want_statement, (
        f"policy statement {policy['definition']['cedar']['statement']!r}, expected {want_statement!r}"
    )

    # Child before parent: an update dropping the Policy removes only it; the PolicyEngine survives.
    cf.update_stack(StackName=stack_id, TemplateBody=_template_without_policy(role_name, pe_name),
                    Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"policy-removing update ended {status!r}"
    policy_not_found = (
        "ResourceNotFoundException", f"Policy with ID {out['PolicyId']} not found",
    )
    expect_error(
        lambda: control.get_policy(policyEngineId=out["PolicyEngineId"], policyId=out["PolicyId"]),
        *policy_not_found,
    )
    still_pe = control.get_policy_engine(policyEngineId=out["PolicyEngineId"])
    got = (still_pe["status"], still_pe["createdAt"])
    assert got == ("ACTIVE", pe["createdAt"]), f"the same PolicyEngine after child delete: {got!r}"

    delete_stack(cf, stack_id)
    engine_not_found = (
        "ResourceNotFoundException", f"Policy engine with ID {out['PolicyEngineId']} not found",
    )
    expect_error(
        lambda: control.get_policy_engine(policyEngineId=out["PolicyEngineId"]), *engine_not_found,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
