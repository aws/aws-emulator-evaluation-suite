"""deploy-guardrail-version-resource-policy-cfn-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-guardrail-version-resource-policy-cfn-lifecycle"
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

_GUARDRAIL_GONE = ("ResourceNotFoundException", "This guardrail does not exist.")


def _listed_versions(bedrock, guardrail_id: str) -> list[dict]:
    return paginate(bedrock, "list_guardrails", "guardrails", guardrailIdentifier=guardrail_id)


def _listed_named(bedrock, name: str) -> list[dict]:
    return [g for g in paginate(bedrock, "list_guardrails", "guardrails") if g["name"] == name]


def _template(names: dict, principal: str, *, with_children: bool) -> str:
    resources: dict = {
        "Guardrail": {
            "Type": "AWS::Bedrock::Guardrail",
            "Properties": {
                "Name": names["guardrail"],
                "BlockedInputMessaging": names["blocked_input"],
                "BlockedOutputsMessaging": names["blocked_output"],
                "WordPolicyConfig": {"WordsConfig": [{"Text": names["word"]}]},
            },
        },
    }
    outputs: dict = {
        "GuardrailRef": {"Value": {"Ref": "Guardrail"}},
        "GuardrailArn": {"Value": {"Fn::GetAtt": ["Guardrail", "GuardrailArn"]}},
        "GuardrailId": {"Value": {"Fn::GetAtt": ["Guardrail", "GuardrailId"]}},
    }
    if with_children:
        resources["GuardrailVersion"] = {
            "Type": "AWS::Bedrock::GuardrailVersion",
            "Properties": {"GuardrailIdentifier": {"Ref": "Guardrail"}},
        }
        resources["ResourcePolicy"] = {
            "Type": "AWS::Bedrock::ResourcePolicy",
            "Properties": {
                "ResourceArn": {"Fn::GetAtt": ["Guardrail", "GuardrailArn"]},
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": principal},
                            "Action": names["action"],
                            "Resource": {"Fn::GetAtt": ["Guardrail", "GuardrailArn"]},
                        }
                    ],
                },
            },
        }
        outputs["GuardrailVersionRef"] = {"Value": {"Ref": "GuardrailVersion"}}
        outputs["GuardrailVersionNumber"] = {"Value": {"Fn::GetAtt": ["GuardrailVersion", "Version"]}}
        outputs["ResourcePolicyRef"] = {"Value": {"Ref": "ResourcePolicy"}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, "Outputs": outputs})


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A stack's Guardrail, GuardrailVersion and ResourcePolicy have Refs and properties matching
    Bedrock's own reads; a stack update removing the version and policy deletes each while the
    guardrail stays, and deleting the stack removes the guardrail from Bedrock.
    """
    cf = ctx.client("cloudformation")
    bedrock = ctx.client("bedrock")

    names = {
        "guardrail": ctx.unique_name("sim2real-bedrock-gr-"),
        "blocked_input": "this request was blocked by the deployed policy",
        "blocked_output": "this response was blocked by the deployed policy",
        "word": "SIM2REALFORBIDDENTERM",
        "action": "bedrock:ApplyGuardrail",
    }

    principal = f"arn:{cf.meta.partition}:iam::{ctx.account}:root"

    stack_id = create_stack(ctx, cf, ctx.unique_name("sim2real-bedrock-gr-cfn-"),
                            _template(names, principal, with_children=True))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    outputs = stack_outputs(cf, stack_id)
    guardrail_id = outputs["GuardrailId"]
    version_number = outputs["GuardrailVersionNumber"]

    # Each Ref is its type's primary identifier, as Bedrock's own listings report it.
    listed = _listed_named(bedrock, names["guardrail"])
    assert len(listed) == 1, f"expected one guardrail named {names['guardrail']!r}, got {listed!r}"
    guardrail_arn = listed[0]["arn"]
    assert listed[0]["id"] == guardrail_id, (
        f"expected GetAtt GuardrailId {guardrail_id!r} to be the listed id, got {listed[0]['id']!r}"
    )
    assert outputs["GuardrailRef"] == guardrail_arn == outputs["GuardrailArn"], (
        f"expected Ref(Guardrail) and GetAtt GuardrailArn to be the listed ARN, got {outputs!r}"
    )
    numbered_listed = [v for v in _listed_versions(bedrock, guardrail_id) if v["version"] == version_number]
    assert len(numbered_listed) == 1, f"expected version {version_number!r} to be listed, got {numbered_listed!r}"
    assert outputs["GuardrailVersionRef"] == f"{numbered_listed[0]['id']}|{numbered_listed[0]['version']}", (
        f"expected Ref(GuardrailVersion) to be '<guardrail id>|<version>', got {outputs['GuardrailVersionRef']!r}"
    )
    assert outputs["ResourcePolicyRef"] == guardrail_arn, (
        f"expected Ref(ResourcePolicy) to be the guardrail ARN, got {outputs['ResourcePolicyRef']!r}"
    )

    # Read back through Bedrock itself: the resources are real, not only CloudFormation's claim.
    draft = bedrock.get_guardrail(guardrailIdentifier=guardrail_id, guardrailVersion="DRAFT")
    assert draft["name"] == names["guardrail"], f"expected name {names['guardrail']!r}, got {draft['name']!r}"
    assert draft["blockedInputMessaging"] == names["blocked_input"], (
        f"expected blockedInputMessaging {names['blocked_input']!r}, got {draft['blockedInputMessaging']!r}"
    )
    assert draft["blockedOutputsMessaging"] == names["blocked_output"], (
        f"expected blockedOutputsMessaging {names['blocked_output']!r}, got {draft['blockedOutputsMessaging']!r}"
    )
    words = {w["text"] for w in draft["wordPolicy"]["words"]}
    assert words == {names["word"]}, f"expected words {{{names['word']!r}}}, got {words!r}"

    numbered = bedrock.get_guardrail(guardrailIdentifier=guardrail_id, guardrailVersion=version_number)
    assert (numbered["guardrailId"], numbered["version"], numbered["status"]) == (
        guardrail_id, version_number, "READY"
    ), f"expected version {version_number!r} READY, got {numbered['version']!r} {numbered['status']!r}"

    policy = json.loads(bedrock.get_resource_policy(resourceArn=guardrail_arn)["resourcePolicy"])
    statements = policy["Statement"]
    assert len(statements) == 1, f"expected one policy statement, got {statements!r}"
    statement = statements[0]
    assert statement["Effect"] == "Allow", f"expected Effect 'Allow', got {statement!r}"
    assert statement["Action"] == names["action"], f"expected Action {names['action']!r}, got {statement!r}"
    assert statement["Resource"] == guardrail_arn, f"expected Resource to be the guardrail ARN, got {statement!r}"
    assert statement["Principal"]["AWS"] == principal, (
        f"expected the account root principal, got a principal of shape {type(statement['Principal']).__name__}"
    )

    # Removing the version and the policy by stack update deletes each while the guardrail stays.
    cf.update_stack(
        StackName=stack_id,
        TemplateBody=_template(names, principal, with_children=False),
    )
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", (
        f"expected UPDATE_COMPLETE, got {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    deadline = time.monotonic() + 60.0
    while True:
        remaining = sorted(v["version"] for v in _listed_versions(bedrock, guardrail_id))
        if version_number not in remaining or time.monotonic() > deadline:
            break
        time.sleep(3.0)
    assert version_number not in remaining, (
        f"expected version {version_number!r} to be gone after its removal, listed {remaining!r}"
    )
    kept = bedrock.get_guardrail(guardrailIdentifier=guardrail_id, guardrailVersion="DRAFT")
    assert kept["name"] == names["guardrail"], f"expected the guardrail to stay, got {kept['name']!r}"
    after_policy = json.loads(bedrock.get_resource_policy(resourceArn=guardrail_arn)["resourcePolicy"])
    assert after_policy == {}, f"expected an empty resource policy after its removal, got {after_policy!r}"

    # Deleting the stack removes the guardrail from Bedrock, not merely from CloudFormation.
    delete_stack(cf, stack_id)
    expect_error(
        lambda: bedrock.get_guardrail(guardrailIdentifier=guardrail_id, guardrailVersion="DRAFT"),
        *_GUARDRAIL_GONE,
    )
    assert _listed_named(bedrock, names["guardrail"]) == [], "the deleted guardrail is still listed"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
