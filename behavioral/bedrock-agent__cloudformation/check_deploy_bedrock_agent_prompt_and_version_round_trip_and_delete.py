"""deploy-bedrock-agent-prompt-and-version-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-bedrock-agent-prompt-and-version-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["bedrock-agent", "cloudformation"]

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

_VARIANT_NAME = "default"
_TEMPLATE_TEXT = "Hello {{name}}, this is a sim2real behavioral probe prompt."
_DESCRIPTION = "sim2real behavioral probe prompt"


def _missing(resource_type: str) -> str:
    return (
        f"Couldn't perform GetPrompt operation. Failed to retrieve resource type {resource_type} "
        "because it doesn't exist. Check the resource ID and retry your request."
    )


def _template(name: str, *, with_version: bool = True) -> str:
    body = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Prompt": {
                "Type": "AWS::Bedrock::Prompt",
                "Properties": {
                    "Name": name,
                    "Description": _DESCRIPTION,
                    "DefaultVariant": _VARIANT_NAME,
                    "Variants": [{
                        "Name": _VARIANT_NAME,
                        "TemplateType": "TEXT",
                        "TemplateConfiguration": {"Text": {"Text": _TEMPLATE_TEXT}},
                    }],
                },
            },
            "PromptVersion": {
                "Type": "AWS::Bedrock::PromptVersion",
                "Properties": {"PromptArn": {"Fn::GetAtt": ["Prompt", "Arn"]}},
            },
        },
        "Outputs": {
            "PromptArn": {"Value": {"Fn::GetAtt": ["Prompt", "Arn"]}},
            "PromptId": {"Value": {"Fn::GetAtt": ["Prompt", "Id"]}},
            "PromptVersionRef": {"Value": {"Ref": "PromptVersion"}},
            "PromptVersionNumber": {"Value": {"Fn::GetAtt": ["PromptVersion", "Version"]}},
        },
    }
    if not with_version:
        del body["Resources"]["PromptVersion"]
        for key in ("PromptVersionRef", "PromptVersionNumber"):
            del body["Outputs"][key]
    return json.dumps(body)


def _listed(ba, **kwargs) -> list[dict]:
    """Every prompt summary ListPrompts reports for ``kwargs``, all pages read."""
    return paginate(ba, "list_prompts", "promptSummaries", **kwargs)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation Prompt and its PromptVersion read back through bedrock-agent's own
    GetPrompt and ListPrompts with the template's ids, description, variant and text; removing
    the version from the stack deletes it, and deleting the stack removes the prompt.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-bedrock-prompt.html
    """
    ba = ctx.client("bedrock-agent")
    cf = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-prompt-")
    prompt_name = ctx.unique_name("sim2real-prompt-")

    stack_gone = ("ValidationError", f"Stack with id {stack} does not exist")
    version_gone = ("ResourceNotFoundException", _missing("PromptVersion"))
    prompt_gone = ("ResourceNotFoundException", _missing("Prompt"))
    stack_id = create_stack(ctx, cf, stack, _template(prompt_name))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE"

    outputs = stack_outputs(cf, stack_id)
    prompt_arn = outputs["PromptArn"]
    prompt_id = outputs["PromptId"]
    version_ref = outputs["PromptVersionRef"]
    version_number = outputs["PromptVersionNumber"]

    assert version_ref == f"{prompt_arn}:{version_number}", (
        f"expected the version's Ref to be {prompt_arn}:{version_number}, got {version_ref!r}"
    )

    listed = [(p["arn"], p["id"]) for p in _listed(ba) if p["name"] == prompt_name]
    assert listed == [(prompt_arn, prompt_id)], (
        f"expected ListPrompts to name {prompt_name!r} once at the GetAtt Arn and Id, got {listed!r}"
    )
    versions = [p["arn"] for p in _listed(ba, promptIdentifier=prompt_id) if p["version"] == version_number]
    assert versions == [version_ref], (
        f"expected ListPrompts to list version {version_number!r} at the version's Ref "
        f"{version_ref!r}, got {versions!r}"
    )

    draft = ba.get_prompt(promptIdentifier=prompt_id)
    assert (draft["arn"], draft["id"]) == (prompt_arn, prompt_id), (
        f"expected GetPrompt's (arn, id) to equal the GetAtt outputs {(prompt_arn, prompt_id)!r}, "
        f"got {(draft['arn'], draft['id'])!r}"
    )
    assert draft.get("description") == _DESCRIPTION, (
        f"expected description {_DESCRIPTION!r}, bedrock-agent reports {draft.get('description')!r}"
    )
    assert draft["name"] == prompt_name, (
        f"expected the draft prompt name {prompt_name!r}, bedrock-agent reports {draft['name']!r}"
    )
    assert draft["version"] == "DRAFT", (
        f"expected the prompt's own version to be 'DRAFT', bedrock-agent reports "
        f"{draft['version']!r}"
    )
    assert draft["defaultVariant"] == _VARIANT_NAME, (
        f"expected defaultVariant {_VARIANT_NAME!r}, bedrock-agent reports "
        f"{draft['defaultVariant']!r}"
    )
    assert [v["name"] for v in draft["variants"]] == [_VARIANT_NAME], (
        f"expected the one variant {_VARIANT_NAME!r}, bedrock-agent reports {draft['variants']!r}"
    )
    draft_variant = draft["variants"][0]
    assert draft_variant["templateType"] == "TEXT", (
        f"expected templateType 'TEXT', bedrock-agent reports {draft_variant['templateType']!r}"
    )
    assert draft_variant["templateConfiguration"]["text"]["text"] == _TEMPLATE_TEXT, (
        f"expected the variant text {_TEMPLATE_TEXT!r}, bedrock-agent reports "
        f"{draft_variant['templateConfiguration']['text']['text']!r}"
    )

    versioned = ba.get_prompt(promptIdentifier=prompt_id, promptVersion=version_number)
    assert versioned["arn"] == version_ref, (
        f"expected the version's arn to equal its Ref {version_ref!r}, bedrock-agent reports "
        f"{versioned['arn']!r}"
    )
    assert versioned["version"] == version_number, (
        f"expected the created version to report version {version_number!r}, bedrock-agent "
        f"reports {versioned['version']!r}"
    )
    assert versioned["name"] == prompt_name, (
        f"expected the version's name {prompt_name!r}, bedrock-agent reports "
        f"{versioned['name']!r}"
    )
    versioned_variant = next(v for v in versioned["variants"] if v["name"] == _VARIANT_NAME)
    assert versioned_variant["templateConfiguration"]["text"]["text"] == _TEMPLATE_TEXT, (
        f"expected the version's variant text {_TEMPLATE_TEXT!r}, bedrock-agent reports "
        f"{versioned_variant['templateConfiguration']['text']['text']!r}"
    )

    cf.update_stack(StackName=stack_id, TemplateBody=_template(prompt_name, with_version=False))
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"stack {stack!r} ended {status!r}, expected UPDATE_COMPLETE"
    expect_error(lambda: ba.get_prompt(promptIdentifier=prompt_id, promptVersion=version_number),
                 *version_gone)
    assert ba.get_prompt(promptIdentifier=prompt_id)["name"] == prompt_name, (
        "expected the prompt to survive its version's removal from the stack"
    )

    delete_stack(cf, stack_id)
    expect_error(lambda: cf.describe_stacks(StackName=stack), *stack_gone)
    expect_error(lambda: ba.get_prompt(promptIdentifier=prompt_id), *prompt_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
