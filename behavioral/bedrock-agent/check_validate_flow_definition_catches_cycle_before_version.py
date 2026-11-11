"""validate-flow-definition-catches-cycle-before-version."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "validate-flow-definition-catches-cycle-before-version"
GROUP = "server-side"
SERVICES = ["bedrock-agent"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ValidateFlowDefinition flags a cyclic flow, PrepareFlow on it ends Failed, and CreateFlowVersion
    gets ConflictException with the exact message and creates no version; a valid flow prepares and
    versions."""
    bedrock = ctx.client("bedrock-agent")
    role_arn = _create_flow_role(ctx)

    valid_definition = _valid_flow_definition()
    cyclic_definition = _cyclic_flow_definition()

    # ValidateFlowDefinition catches the cycle structurally, without needing a
    # created Flow resource at all.
    validation = bedrock.validate_flow_definition(definition=cyclic_definition)
    cyclic_errors = [
        v for v in validation["validations"]
        if v.get("type") == "CyclicConnection" and v["severity"] == "Error"
    ]
    assert len(cyclic_errors) >= 1, validation["validations"]

    # Positive control: a valid flow prepares and versions cleanly.
    good_flow = _retry_access_denied(
        lambda: bedrock.create_flow(
            name=ctx.unique_name("sim2real-flow-good-"),
            executionRoleArn=role_arn,
            definition=valid_definition,
        )
    )
    good_flow_id = good_flow["id"]
    ctx.on_cleanup(lambda: bedrock.delete_flow(flowIdentifier=good_flow_id, skipResourceInUseCheck=True))

    bedrock.prepare_flow(flowIdentifier=good_flow_id)
    good_after_prepare = _poll_flow_status(ctx, good_flow_id, {"Prepared", "Failed"})
    assert good_after_prepare["status"] == "Prepared", good_after_prepare.get("validations")

    good_version = bedrock.create_flow_version(flowIdentifier=good_flow_id)
    ctx.on_cleanup(
        lambda: bedrock.delete_flow_version(
            flowIdentifier=good_flow_id, flowVersion=good_version["version"], skipResourceInUseCheck=True
        )
    )
    assert good_version["version"] != "DRAFT"

    # Negative: a structurally-cyclic flow is accepted by CreateFlow (schema is valid),
    # but fails to prepare, and CreateFlowVersion is then rejected -- with no version
    # ever materializing for it.
    bad_flow = _retry_access_denied(
        lambda: bedrock.create_flow(
            name=ctx.unique_name("sim2real-flow-cyclic-"),
            executionRoleArn=role_arn,
            definition=cyclic_definition,
        )
    )
    bad_flow_id = bad_flow["id"]
    ctx.on_cleanup(lambda: bedrock.delete_flow(flowIdentifier=bad_flow_id, skipResourceInUseCheck=True))

    bedrock.prepare_flow(flowIdentifier=bad_flow_id)
    bad_after_prepare = _poll_flow_status(ctx, bad_flow_id, {"Prepared", "Failed"})
    assert bad_after_prepare["status"] == "Failed"
    assert any(
        v.get("type") == "CyclicConnection" for v in bad_after_prepare.get("validations", [])
    ), bad_after_prepare.get("validations")

    code, message = _error(lambda: bedrock.create_flow_version(flowIdentifier=bad_flow_id))
    assert code == "ConflictException", code
    assert message == (
        "Couldn't perform CreateFlowVersion operation. The resource that you specified is "
        "currently in status Failed. Retry your request after the resource changes to a valid status."
    ), message

    versions = bedrock.list_flow_versions(flowIdentifier=bad_flow_id)["flowVersionSummaries"]
    numbered_versions = [v for v in versions if v["version"] != "DRAFT"]
    assert numbered_versions == [], versions


def _valid_flow_definition() -> dict:
    return {
        "nodes": [
            {
                "name": "FlowInputNode",
                "type": "Input",
                "outputs": [{"name": "document", "type": "String"}],
                "configuration": {"input": {}},
            },
            {
                "name": "FlowOutputNode",
                "type": "Output",
                "inputs": [{"name": "document", "type": "String", "expression": "$.data"}],
                "configuration": {"output": {}},
            },
        ],
        "connections": [
            {
                "name": "InputToOutput",
                "type": "Data",
                "source": "FlowInputNode",
                "target": "FlowOutputNode",
                "configuration": {"data": {"sourceOutput": "document", "targetInput": "document"}},
            }
        ],
    }


def _cyclic_flow_definition() -> dict:
    """A structurally-valid flow (has Input/Output nodes, no fan-in conflicts) that
    still contains a genuine cycle: NodeA -> NodeB -> NodeC -> NodeA (via NodeA's
    second input "context"). This isolates the cyclic-connection error from the
    unrelated "missing FlowInputNode/FlowOutputNode" structural error."""
    model_id = "amazon.titan-text-lite-v1"

    def prompt_node(name: str, extra_input: bool) -> dict:
        input_vars = [{"name": "topic"}]
        text = "Say something about: {{topic}}"
        inputs = [{"name": "topic", "type": "String", "expression": "$.data"}]
        if extra_input:
            input_vars.append({"name": "context"})
            text = "Topic: {{topic}} Context: {{context}}"
            inputs.append({"name": "context", "type": "String", "expression": "$.data"})
        return {
            "name": name,
            "type": "Prompt",
            "inputs": inputs,
            "outputs": [{"name": "modelCompletion", "type": "String"}],
            "configuration": {
                "prompt": {
                    "sourceConfiguration": {
                        "inline": {
                            "templateType": "TEXT",
                            "templateConfiguration": {"text": {"text": text, "inputVariables": input_vars}},
                            "modelId": model_id,
                            "inferenceConfiguration": {"text": {"temperature": 0.5, "topP": 0.9}},
                        }
                    }
                }
            },
        }

    return {
        "nodes": [
            {
                "name": "FlowInputNode",
                "type": "Input",
                "outputs": [{"name": "document", "type": "String"}],
                "configuration": {"input": {}},
            },
            prompt_node("NodeA", extra_input=True),
            prompt_node("NodeB", extra_input=False),
            prompt_node("NodeC", extra_input=False),
            {
                "name": "FlowOutputNode",
                "type": "Output",
                "inputs": [{"name": "document", "type": "String", "expression": "$.data"}],
                "configuration": {"output": {}},
            },
        ],
        "connections": [
            {
                "name": "InputToA",
                "type": "Data",
                "source": "FlowInputNode",
                "target": "NodeA",
                "configuration": {"data": {"sourceOutput": "document", "targetInput": "topic"}},
            },
            {
                "name": "AtoB",
                "type": "Data",
                "source": "NodeA",
                "target": "NodeB",
                "configuration": {"data": {"sourceOutput": "modelCompletion", "targetInput": "topic"}},
            },
            {
                "name": "BtoC",
                "type": "Data",
                "source": "NodeB",
                "target": "NodeC",
                "configuration": {"data": {"sourceOutput": "modelCompletion", "targetInput": "topic"}},
            },
            {
                "name": "CtoA",
                "type": "Data",
                "source": "NodeC",
                "target": "NodeA",
                "configuration": {"data": {"sourceOutput": "modelCompletion", "targetInput": "context"}},
            },
            {
                "name": "CtoOutput",
                "type": "Data",
                "source": "NodeC",
                "target": "FlowOutputNode",
                "configuration": {"data": {"sourceOutput": "modelCompletion", "targetInput": "document"}},
            },
        ],
    }


def _create_flow_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-bedrock-flow-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "bedrock.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
            "Resource": "*",
        }],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="bedrock-invoke", PolicyDocument=json.dumps(inline_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="bedrock-invoke"))
    return role_arn


def _retry_access_denied(fn, attempts: int = 8, delay: float = 5.0):
    # IAM role creation is eventually consistent; CreateFlow may reject the fresh role's ARN
    # for a few seconds after IAM returns it, as either AccessDeniedException or
    # ValidationException. Retry on that specific window instead of sleeping blind up front.
    from botocore.exceptions import ClientError

    last_error = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("AccessDeniedException", "ValidationException"):
                last_error = exc
                time.sleep(delay)
                continue
            raise
    raise last_error


def _poll_flow_status(ctx, flow_id: str, terminal_statuses: set, timeout_s: float = 120.0):
    bedrock = ctx.client("bedrock-agent")
    deadline = time.monotonic() + timeout_s
    flow = None
    while time.monotonic() < deadline:
        flow = bedrock.get_flow(flowIdentifier=flow_id)
        if flow["status"] in terminal_statuses:
            return flow
        time.sleep(3)
    raise AssertionError(f"flow {flow_id} never reached {terminal_statuses}, last={flow}")


def _error(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn raises; an unexpected success
    raises, so a target that accepts what AWS refuses fails loudly rather than as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
