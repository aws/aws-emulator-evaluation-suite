"""deploy-wisdom-aiprompt-aiguardrail-aiagent-and-their-versions-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-wisdom-aiprompt-aiguardrail-aiagent-and-their-versions-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "qconnect"]

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

_MODEL = "anthropic.claude-sonnet-4-5-20250929-v1:0"
_GEOGRAPHY = {"us": "us", "ca": "us", "eu": "eu", "ap": "apac"}
_PROMPT_TEXT = "prompt: |\n  Answer using {{$.contentExcerpt}} for the query {{$.query}}.\n"


def _model_id(region: str) -> str:
    """The cross-region inference profile of the model for the region's geography."""
    return f"{_GEOGRAPHY.get(region.split('-')[0], 'us')}.{_MODEL}"


def _template(name_prefix: str, model_id: str, children: bool = True) -> str:
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Assistant": {
                "Type": "AWS::Wisdom::Assistant",
                "Properties": {"Name": {"Fn::Sub": f"{name_prefix}-a"}, "Type": "AGENT"},
            },
            "Prompt": {
                "Type": "AWS::Wisdom::AIPrompt",
                "Properties": {
                    "AssistantId": {"Fn::GetAtt": ["Assistant", "AssistantId"]},
                    "Name": {"Fn::Sub": f"{name_prefix}-p"},
                    "Type": "ANSWER_GENERATION",
                    "TemplateType": "TEXT",
                    "ApiFormat": "TEXT_COMPLETIONS",
                    "ModelId": model_id,
                    "TemplateConfiguration": {
                        "TextFullAIPromptEditTemplateConfiguration": {"Text": _PROMPT_TEXT},
                    },
                },
            },
            "PromptVersion": {
                "Type": "AWS::Wisdom::AIPromptVersion",
                "Properties": {
                    "AssistantId": {"Fn::GetAtt": ["Assistant", "AssistantId"]},
                    "AIPromptId": {"Fn::GetAtt": ["Prompt", "AIPromptId"]},
                },
            },
            "Guardrail": {
                "Type": "AWS::Wisdom::AIGuardrail",
                "Properties": {
                    "AssistantId": {"Fn::GetAtt": ["Assistant", "AssistantId"]},
                    "Name": {"Fn::Sub": f"{name_prefix}-g"},
                    "BlockedInputMessaging": "Sorry, this input cannot be processed.",
                    "BlockedOutputsMessaging": "Sorry, this output cannot be shown.",
                    "WordPolicyConfig": {
                        "WordsConfig": [{"Text": "sim2real-forbidden-word"}],
                        "ManagedWordListsConfig": [{"Type": "PROFANITY"}],
                    },
                },
            },
            "GuardrailVersion": {
                "Type": "AWS::Wisdom::AIGuardrailVersion",
                "Properties": {
                    "AssistantId": {"Fn::GetAtt": ["Assistant", "AssistantId"]},
                    "AIGuardrailId": {"Fn::GetAtt": ["Guardrail", "AIGuardrailId"]},
                },
            },
            "Agent": {
                "Type": "AWS::Wisdom::AIAgent",
                "Properties": {
                    "AssistantId": {"Fn::GetAtt": ["Assistant", "AssistantId"]},
                    "Name": {"Fn::Sub": f"{name_prefix}-ag"},
                    "Type": "MANUAL_SEARCH",
                    "Configuration": {
                        "ManualSearchAIAgentConfiguration": {
                            "AnswerGenerationAIPromptId": {"Fn::GetAtt": ["Prompt", "AIPromptId"]},
                        },
                    },
                },
            },
            "AgentVersion": {
                "Type": "AWS::Wisdom::AIAgentVersion",
                "Properties": {
                    "AssistantId": {"Fn::GetAtt": ["Assistant", "AssistantId"]},
                    "AIAgentId": {"Fn::GetAtt": ["Agent", "AIAgentId"]},
                },
            },
        },
        "Outputs": {
            "AssistantId": {"Value": {"Fn::GetAtt": ["Assistant", "AssistantId"]}},
            "PromptId": {"Value": {"Fn::GetAtt": ["Prompt", "AIPromptId"]}},
            "PromptRef": {"Value": {"Ref": "Prompt"}},
            "PromptArn": {"Value": {"Fn::GetAtt": ["Prompt", "AIPromptArn"]}},
            "PromptVersionRef": {"Value": {"Ref": "PromptVersion"}},
            "PromptVersionArn": {"Value": {"Fn::GetAtt": ["PromptVersion", "AIPromptArn"]}},
            "GuardrailId": {"Value": {"Fn::GetAtt": ["Guardrail", "AIGuardrailId"]}},
            "GuardrailRef": {"Value": {"Ref": "Guardrail"}},
            "GuardrailArn": {"Value": {"Fn::GetAtt": ["Guardrail", "AIGuardrailArn"]}},
            "GuardrailVersionRef": {"Value": {"Ref": "GuardrailVersion"}},
            "GuardrailVersionArn": {"Value": {"Fn::GetAtt": ["GuardrailVersion", "AIGuardrailArn"]}},
            "AgentId": {"Value": {"Fn::GetAtt": ["Agent", "AIAgentId"]}},
            "AgentRef": {"Value": {"Ref": "Agent"}},
            "AgentArn": {"Value": {"Fn::GetAtt": ["Agent", "AIAgentArn"]}},
            "AgentVersionRef": {"Value": {"Ref": "AgentVersion"}},
            "AgentVersionArn": {"Value": {"Fn::GetAtt": ["AgentVersion", "AIAgentArn"]}},
        },
    }
    if not children:
        template["Resources"] = {"Assistant": template["Resources"]["Assistant"]}
        template["Outputs"] = {"AssistantId": template["Outputs"]["AssistantId"]}
    return json.dumps(template)


def _own(rows, name):
    """The single entry named ``name`` of a paged list."""
    found = [r for r in rows if r["name"] == name]
    assert len(found) == 1, f"expected one entry named {name!r}, got {found!r}"
    return found[0]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AIPrompt, AIGuardrail, AIAgent and their Versions read back through
    Q in Connect with the template's values, ids and frozen version content; an update dropping
    them empties the assistant's lists, and the stack delete removes the assistant.
    """
    qc = ctx.client("qconnect")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-wisdomai-")
    model_id = _model_id(ctx.region)

    stack_id = create_stack(ctx, cfn, stack, _template(stack, model_id))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)

    # Every id from an independent paged list by declared name; composite Refs compared whole.
    assistant = _own(paginate(qc, "list_assistants", "assistantSummaries"), f"{stack}-a")
    assistant_id = assistant["assistantId"]
    assert (outputs["AssistantId"], assistant["type"]) == (assistant_id, "AGENT"), (
        f"GetAtt AssistantId {outputs['AssistantId']!r}, listed assistant {assistant!r}"
    )
    prompts = paginate(qc, "list_ai_prompts", "aiPromptSummaries", assistantId=assistant_id)
    prompt_id = _own(prompts, f"{stack}-p")["aiPromptId"]
    guardrails = paginate(qc, "list_ai_guardrails", "aiGuardrailSummaries",
                          assistantId=assistant_id)
    guardrail_id = _own(guardrails, f"{stack}-g")["aiGuardrailId"]
    agents = paginate(qc, "list_ai_agents", "aiAgentSummaries", assistantId=assistant_id)
    agent_id = _own(agents, f"{stack}-ag")["aiAgentId"]
    got = {k: outputs[k] for k in ("PromptId", "PromptRef", "PromptVersionRef", "GuardrailId",
                                   "GuardrailRef", "GuardrailVersionRef", "AgentId", "AgentRef",
                                   "AgentVersionRef")}
    want = {
        "PromptId": prompt_id, "PromptRef": f"{prompt_id}|{assistant_id}",
        "PromptVersionRef": f"{assistant_id}|{prompt_id}|1.0",
        "GuardrailId": guardrail_id, "GuardrailRef": f"{guardrail_id}|{assistant_id}",
        "GuardrailVersionRef": f"{assistant_id}|{guardrail_id}|1.0",
        "AgentId": agent_id, "AgentRef": f"{agent_id}|{assistant_id}",
        "AgentVersionRef": f"{assistant_id}|{agent_id}|1.0",
    }
    assert got == want, f"Refs and GetAtt ids {got!r}, expected {want!r}"

    prompt = qc.get_ai_prompt(assistantId=assistant_id, aiPromptId=prompt_id)["aiPrompt"]
    got = (prompt["name"], prompt["assistantId"], prompt["modelId"], prompt["apiFormat"],
           prompt["templateType"], prompt["type"], prompt["aiPromptArn"],
           prompt["templateConfiguration"]["textFullAIPromptEditTemplateConfiguration"]["text"])
    want = (f"{stack}-p", assistant_id, model_id, "TEXT_COMPLETIONS", "TEXT",
            "ANSWER_GENERATION", outputs["PromptArn"], _PROMPT_TEXT)
    assert got == want, f"GetAIPrompt reads {got!r}, expected {want!r}"
    prompt_v1 = qc.get_ai_prompt(assistantId=assistant_id, aiPromptId=f"{prompt_id}:1")["aiPrompt"]
    got = (prompt_v1["aiPromptArn"], prompt_v1["templateConfiguration"])
    assert got == (outputs["PromptVersionArn"], prompt["templateConfiguration"]), (
        f"prompt version 1 reads {got!r}"
    )

    guardrail = qc.get_ai_guardrail(assistantId=assistant_id,
                                    aiGuardrailId=guardrail_id)["aiGuardrail"]
    policy = guardrail["wordPolicyConfig"]
    got = (guardrail["name"], guardrail["assistantId"], guardrail["blockedInputMessaging"],
           guardrail["blockedOutputsMessaging"], [w["text"] for w in policy["wordsConfig"]],
           policy["managedWordListsConfig"], guardrail["aiGuardrailArn"])
    want = (f"{stack}-g", assistant_id, "Sorry, this input cannot be processed.",
            "Sorry, this output cannot be shown.", ["sim2real-forbidden-word"],
            [{"type": "PROFANITY"}], outputs["GuardrailArn"])
    assert got == want, f"GetAIGuardrail reads {got!r}, expected {want!r}"
    guardrail_v1 = qc.get_ai_guardrail(assistantId=assistant_id,
                                       aiGuardrailId=f"{guardrail_id}:1")["aiGuardrail"]
    got = (guardrail_v1["aiGuardrailArn"], guardrail_v1["wordPolicyConfig"])
    assert got == (outputs["GuardrailVersionArn"], policy), f"guardrail version 1 reads {got!r}"

    agent = qc.get_ai_agent(assistantId=assistant_id, aiAgentId=agent_id)["aiAgent"]
    got = (agent["name"], agent["assistantId"], agent["type"], agent["aiAgentArn"],
           agent["configuration"]["manualSearchAIAgentConfiguration"]["answerGenerationAIPromptId"])
    want = (f"{stack}-ag", assistant_id, "MANUAL_SEARCH", outputs["AgentArn"], prompt_id)
    assert got == want, f"GetAIAgent reads {got!r}, expected {want!r}"
    agent_v1 = qc.get_ai_agent(assistantId=assistant_id, aiAgentId=f"{agent_id}:1")["aiAgent"]
    got = (agent_v1["aiAgentArn"], agent_v1["configuration"])
    assert got == (outputs["AgentVersionArn"], agent["configuration"]), (
        f"agent version 1 reads {got!r}"
    )

    # Children before the parent: an update keeping only the assistant removes each child type
    # from the assistant's own lists while the assistant still answers.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(stack, model_id, children=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"child-removing update ended {status!r}"
    left = {
        "prompts": [p["name"] for p in paginate(qc, "list_ai_prompts", "aiPromptSummaries",
                                                assistantId=assistant_id)
                    if p["name"].startswith(stack)],
        "guardrails": [g["name"] for g in paginate(qc, "list_ai_guardrails",
                                                   "aiGuardrailSummaries",
                                                   assistantId=assistant_id)],
        "agents": [a["name"] for a in paginate(qc, "list_ai_agents", "aiAgentSummaries",
                                               assistantId=assistant_id)
                   if a["name"].startswith(stack)],
    }
    assert left == {"prompts": [], "guardrails": [], "agents": []}, (
        f"after dropping the children the assistant still lists {left!r}"
    )
    still = qc.get_assistant(assistantId=assistant_id)["assistant"]
    assert still["assistantId"] == assistant_id, f"the assistant after the update reads {still!r}"

    delete_stack(cfn, stack_id)
    expect_error(lambda: qc.get_assistant(assistantId=assistant_id),
                 *("ResourceNotFoundException", "Assistant does not exist."))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
