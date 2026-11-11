"""flow-numeric-parameter-precision-preserved."""
from __future__ import annotations

import json
import math
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "flow-numeric-parameter-precision-preserved"
GROUP = "server-side"
SERVICES = ["bedrock-agent"]

MODEL_ID = "amazon.titan-text-lite-v1"

# Bedrock flow inference-configuration numbers are float32 server-side, so a decimal
# literal like 0.37 round-trips as the nearest float32 (e.g. 0.3700000047683716), not
# byte-identical to the Python double literal. Tolerance is set to comfortably cover
# float32 rounding noise (~1e-7 relative) while still catching gross precision loss
# (e.g. truncation to 1-2 decimal digits, which would be off by >= 1e-3).
FLOAT32_TOL = 1e-5


def _close(actual: float, expected: float) -> bool:
    return math.isclose(actual, expected, rel_tol=FLOAT32_TOL, abs_tol=FLOAT32_TOL)



@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Floating point inference-configuration values (temperature/topP) inside a flow's
    Prompt node survive CreateFlow and then UpdateFlow round-trips through GetFlow
    without precision loss."""
    bedrock = ctx.client("bedrock-agent")
    role_arn = _create_flow_role(ctx)

    flow_name = ctx.unique_name("sim2real-flow-numeric-")
    definition_v1 = _flow_definition(temperature=0.37, top_p=0.82)

    created = _retry_access_denied(
        lambda: bedrock.create_flow(
            name=flow_name,
            executionRoleArn=role_arn,
            definition=definition_v1,
            tags={"sim2real": CHECK},
        )
    )
    flow_id = created["id"]
    ctx.on_cleanup(lambda: _delete_flow_if_present(bedrock, flow_id))

    got_v1 = bedrock.get_flow(flowIdentifier=flow_id)
    inference_v1 = _prompt_node_inference_config(got_v1["definition"])
    assert _close(inference_v1["temperature"], 0.37), (
        f"expected temperature~=0.37 after create_flow, got {inference_v1['temperature']!r}"
    )
    assert _close(inference_v1["topP"], 0.82), (
        f"expected topP~=0.82 after create_flow, got {inference_v1['topP']!r}"
    )

    definition_v2 = _flow_definition(temperature=0.845, top_p=0.129)
    bedrock.update_flow(
        name=flow_name,
        executionRoleArn=role_arn,
        flowIdentifier=flow_id,
        definition=definition_v2,
    )

    got_v2 = bedrock.get_flow(flowIdentifier=flow_id)
    inference_v2 = _prompt_node_inference_config(got_v2["definition"])
    assert _close(inference_v2["temperature"], 0.845), (
        f"expected temperature~=0.845 after update_flow, got {inference_v2['temperature']!r}"
    )
    assert _close(inference_v2["topP"], 0.129), (
        f"expected topP~=0.129 after update_flow, got {inference_v2['topP']!r}"
    )

    bedrock.delete_flow(flowIdentifier=flow_id, skipResourceInUseCheck=True)
    _assert_flow_gone_and_unmutable(bedrock, flow_id, flow_name, role_arn, definition_v2)


def _flow_definition(temperature: float, top_p: float) -> dict:
    return {
        "nodes": [
            {
                "name": "FlowInputNode",
                "type": "Input",
                "outputs": [{"name": "document", "type": "String"}],
                "configuration": {"input": {}},
            },
            {
                "name": "PromptNode",
                "type": "Prompt",
                "inputs": [{"name": "topic", "type": "String", "expression": "$.data"}],
                "outputs": [{"name": "modelCompletion", "type": "String"}],
                "configuration": {
                    "prompt": {
                        "sourceConfiguration": {
                            "inline": {
                                "templateType": "TEXT",
                                "templateConfiguration": {
                                    "text": {
                                        "text": "Say something about: {{topic}}",
                                        "inputVariables": [{"name": "topic"}],
                                    }
                                },
                                "modelId": MODEL_ID,
                                "inferenceConfiguration": {
                                    "text": {"temperature": temperature, "topP": top_p}
                                },
                            }
                        }
                    }
                },
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
                "name": "InputToPrompt",
                "type": "Data",
                "source": "FlowInputNode",
                "target": "PromptNode",
                "configuration": {"data": {"sourceOutput": "document", "targetInput": "topic"}},
            },
            {
                "name": "PromptToOutput",
                "type": "Data",
                "source": "PromptNode",
                "target": "FlowOutputNode",
                "configuration": {"data": {"sourceOutput": "modelCompletion", "targetInput": "document"}},
            },
        ],
    }


def _prompt_node_inference_config(definition: dict) -> dict:
    for node in definition["nodes"]:
        if node["name"] == "PromptNode":
            return node["configuration"]["prompt"]["sourceConfiguration"]["inline"][
                "inferenceConfiguration"
            ]["text"]
    raise AssertionError("PromptNode not found in returned flow definition")


def _assert_flow_gone_and_unmutable(
    bedrock, flow_id: str, flow_name: str, role_arn: str, definition: dict
) -> None:
    try:
        bedrock.get_flow(flowIdentifier=flow_id)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException from get_flow after delete_flow, got {code!r}"
        )
        assert exc.response["Error"].get("Message") == _not_found("GetFlow", "Flow"), exc.response["Error"]
    else:
        raise AssertionError(f"flow {flow_id} still returned by get_flow after delete_flow")

    try:
        bedrock.update_flow(
            name=flow_name,
            executionRoleArn=role_arn,
            flowIdentifier=flow_id,
            definition=definition,
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException from update_flow on a deleted flow, got {code!r}"
        )
        assert exc.response["Error"].get("Message") == _not_found("UpdateFlow", "Flow"), exc.response["Error"]
    else:
        raise AssertionError(f"update_flow succeeded against deleted flow {flow_id}")


def _delete_flow_if_present(bedrock, flow_id):
    try:
        bedrock.delete_flow(flowIdentifier=flow_id, skipResourceInUseCheck=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _not_found(operation, resource_type):
    return (
        f"Couldn't perform {operation} operation. Failed to retrieve resource type {resource_type} "
        "because it doesn't exist. Check the resource ID and retry your request."
    )


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
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
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
    # IAM role/policy propagation to bedrock.amazonaws.com is eventually consistent; the
    # AccessDeniedException retry loop below (up to 8 * 5s = 40s) is the bounded wait for it,
    # not a fixed sleep.
    return role_arn


def _retry_access_denied(fn, attempts: int = 8, delay: float = 5.0):
    last_error = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                last_error = exc
                time.sleep(delay)
                continue
            raise
    raise last_error


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
