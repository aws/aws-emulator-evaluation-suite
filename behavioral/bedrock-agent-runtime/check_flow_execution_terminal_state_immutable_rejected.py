"""flow-execution-terminal-state-immutable-rejected."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "flow-execution-terminal-state-immutable-rejected"
GROUP = "state-machine"
SERVICES = ["bedrock-agent-runtime"]

_MODEL_ID = "amazon.titan-text-express-v1"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Stopping an already-terminal flow execution is rejected with ConflictException."""
    bedrock_agent = ctx.client("bedrock-agent")
    runtime = ctx.client("bedrock-agent-runtime")

    role_arn = _create_flow_role(ctx)
    flow_id, alias_id = _create_prepared_flow_with_alias(ctx, bedrock_agent, role_arn)

    exec_name = f"exec-{uuid.uuid4().hex[:12]}"
    start = runtime.start_flow_execution(
        flowIdentifier=flow_id,
        flowAliasIdentifier=alias_id,
        flowExecutionName=exec_name,
        inputs=[
            {
                "nodeName": "FlowInputNode",
                "nodeOutputName": "document",
                "content": {"document": "a robot who learns to paint"},
            }
        ],
    )
    execution_arn = start["executionArn"]

    # Positive control: stopping a Running execution succeeds and moves it to Aborted.
    stop_resp = runtime.stop_flow_execution(
        flowIdentifier=flow_id, flowAliasIdentifier=alias_id, executionIdentifier=execution_arn
    )
    assert stop_resp["status"] == "Aborted", (
        f"expected the positive-control StopFlowExecution to report Aborted, got {stop_resp['status']!r}"
    )

    final_status = _poll_flow_execution_status(
        runtime, flow_id, alias_id, execution_arn, timeout_s=60.0
    )
    assert final_status == "Aborted", (
        f"expected GetFlowExecution to converge on Aborted after the positive-control stop, "
        f"last saw {final_status!r}"
    )

    # Negative: stopping the now-terminal execution again is rejected.
    code, message = _error(
        lambda: runtime.stop_flow_execution(
            flowIdentifier=flow_id,
            flowAliasIdentifier=alias_id,
            executionIdentifier=execution_arn,
        )
    )
    assert code == "ConflictException", (
        f"expected StopFlowExecution on an already-Aborted execution to be rejected with "
        f"ConflictException, got code={code!r}"
    )
    expected_message = (
        f"Flow execution {exec_name} is in Aborted status and cannot be aborted."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the execution is still exactly Aborted, not re-mutated by the rejected call.
    unchanged = runtime.get_flow_execution(
        flowIdentifier=flow_id, flowAliasIdentifier=alias_id, executionIdentifier=execution_arn
    )["status"]
    assert unchanged == "Aborted", (
        f"expected the rejected second StopFlowExecution to leave the execution's status "
        f"unchanged at Aborted, but an independent GetFlowExecution read saw {unchanged!r}"
    )


def _error(fn) -> tuple[str, str | None]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected StopFlowExecution on an already-terminal execution to be rejected, but it "
        f"SUCCEEDED and returned {result!r}"
    )


def _create_flow_role(ctx) -> str:
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region

    role_name = ctx.unique_name("sim2real-bedflowrole2-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {
                        "aws:SourceArn": f"arn:aws:bedrock:{region}:{account_id}:flow/*"
                    },
                },
            }
        ],
    }

    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))

    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="invoke-model",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "bedrock:InvokeModel",
                        "Resource": f"arn:aws:bedrock:{region}::foundation-model/*",
                    }
                ],
            }
        ),
    )
    return role_arn


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="invoke-model")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _flow_definition() -> dict:
    input_node = {
        "name": "FlowInputNode",
        "type": "Input",
        "outputs": [{"name": "document", "type": "String"}],
    }
    prompt_node = {
        "name": "PromptNode",
        "type": "Prompt",
        "configuration": {
            "prompt": {
                "sourceConfiguration": {
                    "inline": {
                        "modelId": _MODEL_ID,
                        "templateType": "TEXT",
                        "inferenceConfiguration": {
                            "text": {"temperature": 0.7, "maxTokens": 1024}
                        },
                        "templateConfiguration": {
                            "text": {
                                "text": (
                                    "Write a detailed 300-word short story about {{topic}}."
                                )
                            }
                        },
                    }
                }
            }
        },
        "inputs": [{"name": "topic", "type": "String", "expression": "$.data"}],
        "outputs": [{"name": "modelCompletion", "type": "String"}],
    }
    output_node = {
        "name": "FlowOutputNode",
        "type": "Output",
        "inputs": [{"name": "document", "type": "String", "expression": "$.data"}],
    }
    connections = [
        {
            "name": "input_to_prompt",
            "source": "FlowInputNode",
            "target": "PromptNode",
            "type": "Data",
            "configuration": {"data": {"sourceOutput": "document", "targetInput": "topic"}},
        },
        {
            "name": "prompt_to_output",
            "source": "PromptNode",
            "target": "FlowOutputNode",
            "type": "Data",
            "configuration": {
                "data": {"sourceOutput": "modelCompletion", "targetInput": "document"}
            },
        },
    ]
    return {"nodes": [input_node, prompt_node, output_node], "connections": connections}


def _create_prepared_flow_with_alias(ctx, bedrock_agent: Any, role_arn: str) -> tuple[str, str]:
    flow_name = ctx.unique_name("sim2real-flow2-")
    definition = _flow_definition()

    flow_id = None
    last_err: Exception | None = None
    for attempt in range(8):
        try:
            resp = bedrock_agent.create_flow(
                name=flow_name,
                executionRoleArn=role_arn,
                definition=definition,
                tags={"sim2real": CHECK},
            )
            flow_id = resp["id"]
            break
        except ClientError as e:
            last_err = e
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException") and attempt < 7:
                time.sleep(5)
                continue
            raise
    if flow_id is None:
        raise last_err  # pragma: no cover

    ctx.on_cleanup(lambda: _delete_flow(ctx, bedrock_agent, flow_id))

    bedrock_agent.prepare_flow(flowIdentifier=flow_id)
    deadline = time.monotonic() + 60.0
    status = None
    while time.monotonic() < deadline:
        status = bedrock_agent.get_flow(flowIdentifier=flow_id)["status"]
        if status in ("Prepared", "Failed"):
            break
        time.sleep(3)
    assert status == "Prepared", f"flow did not prepare in time (status={status})"

    version = bedrock_agent.create_flow_version(flowIdentifier=flow_id)["version"]
    alias_name = ctx.unique_name("sim2real-alias2-")
    alias = bedrock_agent.create_flow_alias(
        flowIdentifier=flow_id,
        name=alias_name,
        routingConfiguration=[{"flowVersion": version}],
    )
    return flow_id, alias["id"]


def _delete_flow(ctx, bedrock_agent: Any, flow_id: str) -> None:
    try:
        for alias in bedrock_agent.list_flow_aliases(flowIdentifier=flow_id).get(
            "flowAliasSummaries", []
        ):
            try:
                bedrock_agent.delete_flow_alias(flowIdentifier=flow_id, aliasIdentifier=alias["id"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        bedrock_agent.delete_flow(flowIdentifier=flow_id, skipResourceInUseCheck=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_flow_execution_status(
    runtime: Any, flow_id: str, alias_id: str, execution_arn: str, *, timeout_s: float = 60.0
) -> str:
    deadline = time.monotonic() + timeout_s
    status = "Running"
    while time.monotonic() < deadline:
        status = runtime.get_flow_execution(
            flowIdentifier=flow_id,
            flowAliasIdentifier=alias_id,
            executionIdentifier=execution_arn,
        )["status"]
        if status != "Running":
            return status
        time.sleep(2)
    return status


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
