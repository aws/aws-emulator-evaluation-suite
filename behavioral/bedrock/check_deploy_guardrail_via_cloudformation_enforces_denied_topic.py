"""deploy-guardrail-via-cloudformation-enforces-denied-topic."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-guardrail-via-cloudformation-enforces-denied-topic"
GROUP = "server-side"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """An AWS::Bedrock::Guardrail stack reaches CREATE_COMPLETE with a GuardrailArn in the caller's
    account, the guardrail is READY and ApplyGuardrail blocks its denied topic, as it does for a
    guardrail with the same topic policy created directly through the Bedrock API.
    """
    cfn = ctx.client("cloudformation")
    bedrock_rt = ctx.client("bedrock-runtime")
    bedrock = ctx.client("bedrock")
    sts = ctx.client("sts")
    caller_account = sts.get_caller_identity()["Account"]

    topic_name = "MedicalDosageAdvice"
    topic_definition = (
        "Providing specific medical dosage or treatment advice for a named medical condition."
    )
    topic_examples = ["What dose of insulin should I take for my diabetes?"]
    api_topic_config = {
        "name": topic_name,
        "definition": topic_definition,
        "examples": topic_examples,
        "type": "DENY",
    }
    cfn_topic_config = {
        "Name": topic_name,
        "Definition": topic_definition,
        "Examples": topic_examples,
        "Type": "DENY",
    }
    denied_prompt = (
        "I have type 2 diabetes. What dose of insulin should I inject each morning?"
    )

    # ---- Positive control: the same topic policy, created directly through the Bedrock
    # control plane (no CloudFormation involved). Proves the account/credentials/guardrail
    # feature are healthy, and that ApplyGuardrail really enforces this denied topic when the
    # guardrail is actually reachable.
    control_name = ctx.unique_name("sim2real-bedrock-gr-control-")
    control = bedrock.create_guardrail(
        name=control_name,
        blockedInputMessaging="This request was blocked by policy.",
        blockedOutputsMessaging="This response was blocked by policy.",
        topicPolicyConfig={"topicsConfig": [api_topic_config]},
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    control_id = control["guardrailId"]
    ctx.on_cleanup(lambda: bedrock.delete_guardrail(guardrailIdentifier=control_id))
    _wait_guardrail_ready(bedrock, control_id, timeout_s=120.0)

    control_resp = bedrock_rt.apply_guardrail(
        guardrailIdentifier=control_id,
        guardrailVersion="DRAFT",
        source="INPUT",
        content=[{"text": {"text": denied_prompt}}],
    )
    assert control_resp["action"] == "GUARDRAIL_INTERVENED", control_resp
    control_topics = control_resp["assessments"][0]["topicPolicy"]["topics"]
    control_matched = [t for t in control_topics if t["name"] == topic_name]
    assert control_matched, (
        f"denied topic {topic_name} not present in control assessment: {control_topics}"
    )
    assert control_matched[0]["action"] == "BLOCKED", control_matched[0]
    assert control_matched[0]["detected"] is True, control_matched[0]

    # ---- The subject under test: the same guardrail shape, deployed via CloudFormation.
    stack_name = ctx.unique_name("sim2real-bedrock-gr-stack-")
    guardrail_name = ctx.unique_name("sim2real-bedrock-gr-")
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Guardrail": {
                "Type": "AWS::Bedrock::Guardrail",
                "Properties": {
                    "Name": guardrail_name,
                    "BlockedInputMessaging": "This request was blocked by policy.",
                    "BlockedOutputsMessaging": "This response was blocked by policy.",
                    "TopicPolicyConfig": {"TopicsConfig": [cfn_topic_config]},
                    "Tags": [{"Key": "sim2real-check", "Value": CHECK}],
                },
            }
        },
        "Outputs": {
            "GuardrailId": {"Value": {"Fn::GetAtt": ["Guardrail", "GuardrailId"]}},
            "GuardrailArn": {"Value": {"Fn::GetAtt": ["Guardrail", "GuardrailArn"]}},
        },
    }

    def _cleanup_stack() -> None:
        from botocore.exceptions import ClientError

        cfn.delete_stack(StackName=stack_name)
        try:
            _wait_stack_status(cfn, stack_name, {"DELETE_COMPLETE"}, timeout_s=300.0)
        except ClientError as exc:
            # A fully deleted stack does not resolve by name.
            if exc.response["Error"]["Code"] != "ValidationError":
                raise

    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template))
    ctx.on_cleanup(_cleanup_stack)

    stack = _wait_stack_status(cfn, stack_name, {"CREATE_COMPLETE"}, timeout_s=300.0)
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    assert "GuardrailId" in outputs, stack.get("Outputs")
    guardrail_arn = outputs.get("GuardrailArn", "")
    assert f":{caller_account}:" in guardrail_arn, (
        "expected the CFN-reported GuardrailArn to be scoped to the caller's own account "
        f"{caller_account!r}, got {guardrail_arn!r}"
    )
    guardrail_id = guardrail_arn or outputs["GuardrailId"]

    # The CFN-provisioned guardrail is reachable and READY under the same identity.
    _wait_guardrail_ready(bedrock, guardrail_id, timeout_s=120.0)

    # Data plane: the CFN-provisioned guardrail blocks the denied topic exactly like the control.
    resp = bedrock_rt.apply_guardrail(
        guardrailIdentifier=guardrail_id,
        guardrailVersion="DRAFT",
        source="INPUT",
        content=[{"text": {"text": denied_prompt}}],
    )
    assert resp["action"] == "GUARDRAIL_INTERVENED", resp
    topics = resp["assessments"][0]["topicPolicy"]["topics"]
    matched = [t for t in topics if t["name"] == topic_name]
    assert matched, f"denied topic {topic_name} not present in the CFN guardrail assessment: {topics}"
    assert matched[0]["action"] == "BLOCKED", matched[0]
    assert matched[0]["detected"] is True, matched[0]


def _wait_stack_status(
    cfn: Any,
    stack_name: str,
    target_statuses: set[str],
    timeout_s: float = 300.0,
    interval_s: float = 10.0,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        stack = resp["Stacks"][0]
        last_status = stack["StackStatus"]
        if last_status in target_statuses:
            return stack
        if last_status.endswith("FAILED") or last_status == "ROLLBACK_COMPLETE":
            raise AssertionError(f"stack {stack_name} entered {last_status}")
        time.sleep(interval_s)
    raise AssertionError(
        f"stack {stack_name} did not reach {target_statuses}, last status {last_status}"
    )


def _wait_guardrail_ready(
    bedrock: Any,
    guardrail_id: str,
    timeout_s: float = 120.0,
    interval_s: float = 3.0,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = bedrock.get_guardrail(guardrailIdentifier=guardrail_id)
        last_status = resp["status"]
        if last_status == "READY":
            return resp
        if last_status == "FAILED":
            raise AssertionError(f"guardrail {guardrail_id} failed: {resp.get('statusReasons')}")
        time.sleep(interval_s)
    raise AssertionError(
        f"guardrail {guardrail_id} did not reach READY, last status {last_status}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
