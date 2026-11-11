"""deploy-enforced-guardrail-configuration-cfn-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-enforced-guardrail-configuration-cfn-lifecycle"
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

# Enforcement is scoped to one model no other check invokes, so siblings' inference is unaffected.
_ENFORCED_MODEL = "cohere.command-r-v1:0"
_GUARDRAIL_GONE = ("ResourceNotFoundException", "This guardrail does not exist.")


def _configs(bedrock) -> list[dict]:
    return paginate(bedrock, "list_enforced_guardrails_configuration", "guardrailsConfig")


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:deploy",
    "concern:representation",
    "plane:control",
    "resource:account-singleton:bedrock-enforced-guardrail",
)
def run(ctx) -> None:
    """A stack's Guardrail, GuardrailVersion and model-scoped EnforcedGuardrailConfiguration read
    back through Bedrock with the template's values and Ref/GetAtt; deleting the stack removes the
    enforcement and the guardrail, restoring the account's prior enforced-configuration set.
    """
    cf = ctx.client("cloudformation")
    bedrock = ctx.client("bedrock")

    prior = _configs(bedrock)
    prior_account_owned = [c for c in prior if c.get("owner") == "ACCOUNT"]
    assert prior_account_owned == [], (
        "precondition: the account already enforces a guardrail configuration of its own; "
        f"found {len(prior_account_owned)} account-owned configuration(s)"
    )
    prior_ids = {c["configId"] for c in prior}

    stack_name = ctx.unique_name("sim2real-bedrock-egc-cfn-")
    guardrail_name = ctx.unique_name("sim2real-bedrock-egc-")
    blocked_input = "blocked input"
    blocked_output = "blocked output"
    forbidden_word = "SIM2REALENFORCEDFORBIDDEN"

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Guardrail": {
                "Type": "AWS::Bedrock::Guardrail",
                "Properties": {
                    "Name": guardrail_name,
                    "BlockedInputMessaging": blocked_input,
                    "BlockedOutputsMessaging": blocked_output,
                    "WordPolicyConfig": {"WordsConfig": [{"Text": forbidden_word}]},
                },
            },
            "GuardrailVersion": {
                "Type": "AWS::Bedrock::GuardrailVersion",
                "Properties": {"GuardrailIdentifier": {"Ref": "Guardrail"}},
            },
            "EnforcedConfig": {
                "Type": "AWS::Bedrock::EnforcedGuardrailConfiguration",
                "Properties": {
                    "GuardrailIdentifier": {"Fn::GetAtt": ["Guardrail", "GuardrailId"]},
                    "GuardrailVersion": {"Fn::GetAtt": ["GuardrailVersion", "Version"]},
                    "ModelEnforcement": {"IncludedModels": [_ENFORCED_MODEL], "ExcludedModels": []},
                },
            },
        },
        "Outputs": {
            "ConfigId": {"Value": {"Ref": "EnforcedConfig"}},
            "ConfigGuardrailArn": {"Value": {"Fn::GetAtt": ["EnforcedConfig", "GuardrailArn"]}},
            "ConfigGuardrailId": {"Value": {"Fn::GetAtt": ["EnforcedConfig", "GuardrailId"]}},
            "ConfigOwner": {"Value": {"Fn::GetAtt": ["EnforcedConfig", "Owner"]}},
            "GuardrailRef": {"Value": {"Ref": "Guardrail"}},
            "GuardrailId": {"Value": {"Fn::GetAtt": ["Guardrail", "GuardrailId"]}},
            "GuardrailVersionNumber": {"Value": {"Fn::GetAtt": ["GuardrailVersion", "Version"]}},
        },
    }

    stack_id = create_stack(ctx, cf, stack_name, json.dumps(template))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    outputs = stack_outputs(cf, stack_id)
    guardrail_id = outputs["GuardrailId"]
    version_number = outputs["GuardrailVersionNumber"]

    # The guardrail and its version are real in Bedrock, with the template's properties.
    draft = bedrock.get_guardrail(guardrailIdentifier=guardrail_id, guardrailVersion="DRAFT")
    assert draft["guardrailArn"] == outputs["GuardrailRef"], (
        f"expected Ref(Guardrail) {outputs['GuardrailRef']!r} to be the guardrail ARN, got {draft['guardrailArn']!r}"
    )
    assert draft["name"] == guardrail_name, f"expected name {guardrail_name!r}, got {draft['name']!r}"
    assert draft["blockedInputMessaging"] == blocked_input, (
        f"expected blockedInputMessaging {blocked_input!r}, got {draft['blockedInputMessaging']!r}"
    )
    assert draft["blockedOutputsMessaging"] == blocked_output, (
        f"expected blockedOutputsMessaging {blocked_output!r}, got {draft['blockedOutputsMessaging']!r}"
    )
    words = {w["text"] for w in draft["wordPolicy"]["words"]}
    assert words == {forbidden_word}, f"expected words {{{forbidden_word!r}}}, got {words!r}"
    numbered = bedrock.get_guardrail(guardrailIdentifier=guardrail_id, guardrailVersion=version_number)
    assert (numbered["version"], numbered["status"]) == (version_number, "READY"), (
        f"expected version {version_number!r} READY, got {(numbered['version'], numbered['status'])!r}"
    )

    # Ref is the configId Bedrock lists for this guardrail; the read-only GetAtts match the listing.
    own = [c for c in _configs(bedrock) if c["guardrailId"] == guardrail_id]
    assert len(own) == 1, f"expected one enforced configuration for the guardrail, got {own!r}"
    entry = own[0]
    assert entry["configId"] == outputs["ConfigId"], (
        f"expected Ref(EnforcedConfig) {outputs['ConfigId']!r} to be the listed configId, got {entry['configId']!r}"
    )
    assert entry["guardrailArn"] == draft["guardrailArn"] == outputs["ConfigGuardrailArn"], (
        f"expected GetAtt GuardrailArn {outputs['ConfigGuardrailArn']!r}, got {entry['guardrailArn']!r}"
    )
    assert entry["guardrailId"] == outputs["ConfigGuardrailId"], (
        f"expected GetAtt GuardrailId {outputs['ConfigGuardrailId']!r}, got {entry['guardrailId']!r}"
    )
    assert entry["owner"] == outputs["ConfigOwner"] == "ACCOUNT", (
        f"expected owner 'ACCOUNT' from both reads, got {entry['owner']!r} and {outputs['ConfigOwner']!r}"
    )
    assert entry["guardrailVersion"] == version_number, (
        f"expected guardrailVersion {version_number!r}, got {entry['guardrailVersion']!r}"
    )
    enforcement = entry["modelEnforcement"]
    assert enforcement["includedModels"] == [_ENFORCED_MODEL], (
        f"expected includedModels [{_ENFORCED_MODEL!r}], got {enforcement!r}"
    )
    assert enforcement.get("excludedModels", []) == [], f"expected no excludedModels, got {enforcement!r}"

    # Deleting the stack removes the enforcement and the guardrail from Bedrock.
    delete_stack(cf, stack_id)
    after = _configs(bedrock)
    assert [c for c in after if c["configId"] == entry["configId"]] == [], (
        f"configuration {entry['configId']!r} is still enforced after the stack delete"
    )
    assert {c["configId"] for c in after} == prior_ids, (
        f"expected the account's enforced set to return to its {len(prior_ids)} prior configuration(s), "
        f"got {len(after)}"
    )
    expect_error(
        lambda: bedrock.get_guardrail(guardrailIdentifier=guardrail_id, guardrailVersion="DRAFT"),
        *_GUARDRAIL_GONE,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
