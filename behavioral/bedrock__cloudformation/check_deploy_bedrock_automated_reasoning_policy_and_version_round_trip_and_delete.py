"""deploy-bedrock-automated-reasoning-policy-and-version-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-bedrock-automated-reasoning-policy-and-version-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["bedrock", "cloudformation"]

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

_DEFINITION = {
    "Version": "1.0",
    "Types": [],
    "Variables": [
        {"Name": "isRaining", "Type": "BOOL", "Description": "Whether it is currently raining."},
        {"Name": "temperature", "Type": "NUMBER", "Description": "The outdoor temperature in C."},
    ],
    "Rules": [{"Id": "R00000000001", "Expression": "(=> isRaining (< temperature 30))"}],
}
_DESCRIPTION = "sim2real behavioral probe policy"


def _template(name: str, *, with_version: bool = True) -> str:
    body = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Policy": {
                "Type": "AWS::Bedrock::AutomatedReasoningPolicy",
                "Properties": {
                    "Name": name,
                    "Description": _DESCRIPTION,
                    "PolicyDefinition": _DEFINITION,
                },
            },
            "PolicyVersion": {
                "Type": "AWS::Bedrock::AutomatedReasoningPolicyVersion",
                "Properties": {
                    "PolicyArn": {"Ref": "Policy"},
                    "LastUpdatedDefinitionHash": {"Fn::GetAtt": ["Policy", "DefinitionHash"]},
                },
            },
        },
        "Outputs": {
            "PolicyArn": {"Value": {"Ref": "Policy"}},
            "PolicyDefinitionHash": {"Value": {"Fn::GetAtt": ["Policy", "DefinitionHash"]}},
            "PolicyVersionRef": {"Value": {"Ref": "PolicyVersion"}},
            "PolicyVersionDefinitionHash": {
                "Value": {"Fn::GetAtt": ["PolicyVersion", "DefinitionHash"]}
            },
            "PolicyVersionNumber": {"Value": {"Fn::GetAtt": ["PolicyVersion", "Version"]}},
        },
    }
    if not with_version:
        del body["Resources"]["PolicyVersion"]
        for key in ("PolicyVersionRef", "PolicyVersionDefinitionHash", "PolicyVersionNumber"):
            del body["Outputs"][key]
    return json.dumps(body)


def _assert_definition(exported: dict, label: str) -> None:
    """The exported definition carries the template's types, variables and rules."""
    got_vars = sorted((v["name"], v["type"], v["description"]) for v in exported["variables"])
    want_vars = sorted((v["Name"], v["Type"], v["Description"]) for v in _DEFINITION["Variables"])
    assert got_vars == want_vars, f"expected the {label}'s variables {want_vars!r}, got {got_vars!r}"
    got_rules = sorted((r["id"], r["expression"]) for r in exported["rules"])
    want_rules = sorted((r["Id"], r["Expression"]) for r in _DEFINITION["Rules"])
    assert got_rules == want_rules, f"expected the {label}'s rules {want_rules!r}, got {got_rules!r}"
    assert exported["types"] == [], f"expected the {label} to declare no types, got {exported['types']!r}"


def _listed(bedrock, **kwargs) -> list[dict]:
    """Every policy summary ListAutomatedReasoningPolicies reports for ``kwargs``, all pages read."""
    return paginate(bedrock, "list_automated_reasoning_policies",
                    "automatedReasoningPolicySummaries", **kwargs)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AutomatedReasoningPolicy and its PolicyVersion read back through Bedrock
    with the template's name, description and definition; removing the version from the stack
    deletes it, and deleting the stack removes the policy.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-bedrock-automatedreasoningpolicy.html
    """
    bedrock = ctx.client("bedrock")
    cf = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-arpolicy-")
    policy_name = ctx.unique_name("sim2real-arpolicy-")

    stack_gone = ("ValidationError", f"Stack with id {stack} does not exist")
    version_gone = ("ResourceNotFoundException", "Policy version does not exist")
    policy_gone = ("ResourceNotFoundException", "Policy does not exist")
    stack_id = create_stack(ctx, cf, stack, _template(policy_name))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE"

    outputs = stack_outputs(cf, stack_id)
    policy_arn = outputs["PolicyArn"]
    def_hash = outputs["PolicyDefinitionHash"]
    version_ref = outputs["PolicyVersionRef"]
    version_def_hash = outputs["PolicyVersionDefinitionHash"]
    version_number = outputs["PolicyVersionNumber"]

    assert version_ref == f"{policy_arn}|{version_number}", (
        f"expected the version's Ref to join PolicyArn and Version with '|', got {version_ref!r}"
    )

    listed = [p["policyArn"] for p in _listed(bedrock) if p["name"] == policy_name]
    assert listed == [policy_arn], (
        f"expected Bedrock to list {policy_name!r} once at the stack's Ref {policy_arn!r}, got {listed!r}"
    )

    draft = bedrock.get_automated_reasoning_policy(policyArn=policy_arn)
    assert draft["policyArn"] == policy_arn, (
        f"expected the policy's policyArn to equal the Ref {policy_arn!r}, Bedrock reports "
        f"{draft['policyArn']!r}"
    )
    assert draft.get("description") == _DESCRIPTION, (
        f"expected description {_DESCRIPTION!r}, Bedrock reports {draft.get('description')!r}"
    )
    _assert_definition(
        bedrock.export_automated_reasoning_policy_version(policyArn=policy_arn)["policyDefinition"],
        "draft policy",
    )
    assert draft["name"] == policy_name, (
        f"expected the draft policy name to be {policy_name!r}, Bedrock reports {draft['name']!r}"
    )
    assert draft["version"] == "DRAFT", (
        f"expected the policy's own version to be 'DRAFT', Bedrock reports {draft['version']!r}"
    )
    assert draft["definitionHash"] == def_hash, (
        f"expected the draft definitionHash {def_hash!r}, Bedrock reports "
        f"{draft['definitionHash']!r}"
    )

    versioned_arn = f"{policy_arn}:{version_number}"
    versioned = bedrock.get_automated_reasoning_policy(policyArn=versioned_arn)
    assert versioned["version"] == version_number, (
        f"expected the created version to report version {version_number!r}, Bedrock reports "
        f"{versioned['version']!r}"
    )
    assert versioned["definitionHash"] == version_def_hash, (
        f"expected the version's definitionHash {version_def_hash!r}, Bedrock reports "
        f"{versioned['definitionHash']!r}"
    )
    assert versioned["definitionHash"] == def_hash, (
        f"expected the version to snapshot the policy's definitionHash {def_hash!r}, Bedrock "
        f"reports {versioned['definitionHash']!r}"
    )
    assert versioned["policyArn"] == versioned_arn, (
        f"expected the version's policyArn {versioned_arn!r}, Bedrock reports {versioned['policyArn']!r}"
    )
    _assert_definition(
        bedrock.export_automated_reasoning_policy_version(policyArn=versioned_arn)["policyDefinition"],
        "policy version",
    )

    cf.update_stack(StackName=stack_id, TemplateBody=_template(policy_name, with_version=False))
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"stack {stack!r} ended {status!r}, expected UPDATE_COMPLETE"
    expect_error(lambda: bedrock.get_automated_reasoning_policy(policyArn=versioned_arn),
                 *version_gone)
    assert bedrock.get_automated_reasoning_policy(policyArn=policy_arn)["name"] == policy_name, (
        "expected the policy to survive its version's removal from the stack"
    )

    delete_stack(cf, stack_id)
    expect_error(lambda: cf.describe_stacks(StackName=stack), *stack_gone)
    expect_error(lambda: bedrock.get_automated_reasoning_policy(policyArn=policy_arn), *policy_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
