"""flow-execution-events-ordering."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "flow-execution-events-ordering"
GROUP = "ordering"
SERVICES = ["bedrock-agent-runtime"]

_INPUT_NODE = "FlowInputNode"
_OUTPUT_NODE = "FlowOutputNode"


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A completed two-node flow execution's ListFlowExecutionEvents has non-decreasing timestamps, and
    the input node's nodeOutputEvent precedes the output node's nodeInputEvent."""
    iam = ctx.client("iam")
    agent = ctx.client("bedrock-agent")
    runtime = ctx.client("bedrock-agent-runtime")

    role_name = ctx.unique_name("sim2real-bar-flowrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "bedrock.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description="sim2real test role for a Bedrock flow (input->output only)",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "bedrock:GetFlow", "Resource": "*"}],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    flow_def = {
        "nodes": [
            {"type": "Input", "name": _INPUT_NODE, "outputs": [{"name": "document", "type": "String"}]},
            {
                "type": "Output",
                "name": _OUTPUT_NODE,
                "inputs": [{"name": "document", "type": "String", "expression": "$.data"}],
            },
        ],
        "connections": [
            {
                "name": "InputToOutput",
                "source": _INPUT_NODE,
                "target": _OUTPUT_NODE,
                "type": "Data",
                "configuration": {"data": {"sourceOutput": "document", "targetInput": "document"}},
            }
        ],
    }

    flow_name = ctx.unique_name("sim2real-bar-flow-")
    flow = _retry_on_role_propagation(
        lambda: agent.create_flow(
            name=flow_name, executionRoleArn=role_arn, definition=flow_def, tags={"sim2real": CHECK}
        ),
    )
    flow_id = flow["id"]
    ctx.on_cleanup(lambda: agent.delete_flow(flowIdentifier=flow_id, skipResourceInUseCheck=True))

    _retry_on_role_propagation(lambda: agent.prepare_flow(flowIdentifier=flow_id))
    _poll_until(
        lambda: agent.get_flow(flowIdentifier=flow_id)["status"],
        lambda status: status == "Prepared",
        timeout_s=120.0,
        interval_s=3.0,
        description="flow status to reach Prepared",
    )

    version = agent.create_flow_version(flowIdentifier=flow_id)["version"]
    ctx.on_cleanup(lambda: agent.delete_flow_version(flowIdentifier=flow_id, flowVersion=version))

    alias_name = ctx.unique_name("sim2real-bar-alias-")
    alias_id = agent.create_flow_alias(
        flowIdentifier=flow_id,
        name=alias_name,
        routingConfiguration=[{"flowVersion": version}],
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: agent.delete_flow_alias(flowIdentifier=flow_id, aliasIdentifier=alias_id))

    execution_arn = _retry_on_role_propagation(
        lambda: runtime.start_flow_execution(
            flowIdentifier=flow_id,
            flowAliasIdentifier=alias_id,
            inputs=[
                {
                    "nodeName": _INPUT_NODE,
                    "nodeOutputName": "document",
                    "content": {"document": "hello-flow-events"},
                }
            ],
        ),
    )["executionArn"]

    final_status = _poll_until(
        lambda: runtime.get_flow_execution(
            flowIdentifier=flow_id, flowAliasIdentifier=alias_id, executionIdentifier=execution_arn
        )["status"],
        lambda status: status in ("Succeeded", "Failed", "TimedOut", "Aborted"),
        timeout_s=120.0,
        interval_s=3.0,
        description="flow execution to reach a terminal status",
    )
    assert final_status == "Succeeded", f"expected flow execution to succeed, got {final_status}"

    events_resp = runtime.list_flow_execution_events(
        flowIdentifier=flow_id,
        flowAliasIdentifier=alias_id,
        executionIdentifier=execution_arn,
        eventType="Node",
        maxResults=50,
    )
    events = events_resp["flowExecutionEvents"]
    assert len(events) >= 2, f"expected at least a nodeInputEvent and nodeOutputEvent, got {events}"

    timestamps = []
    input_node_output_idx = None
    output_node_input_idx = None
    for idx, event in enumerate(events):
        if "nodeInputEvent" in event:
            timestamps.append(event["nodeInputEvent"]["timestamp"])
            if event["nodeInputEvent"]["nodeName"] == _OUTPUT_NODE:
                output_node_input_idx = idx
        elif "nodeOutputEvent" in event:
            timestamps.append(event["nodeOutputEvent"]["timestamp"])
            if event["nodeOutputEvent"]["nodeName"] == _INPUT_NODE:
                input_node_output_idx = idx

    for i in range(1, len(timestamps)):
        assert timestamps[i - 1] <= timestamps[i], (
            f"flow execution node event timestamps are not chronological: {timestamps}"
        )

    assert input_node_output_idx is not None, (
        f"expected {_INPUT_NODE} to emit a nodeOutputEvent, got {events}"
    )
    assert output_node_input_idx is not None, (
        f"expected {_OUTPUT_NODE} to emit a nodeInputEvent, got {events}"
    )
    assert input_node_output_idx < output_node_input_idx, (
        f"{_INPUT_NODE}'s nodeOutputEvent must precede {_OUTPUT_NODE}'s nodeInputEvent for the same "
        f"data flowing through the connection: input-node-output at {input_node_output_idx}, "
        f"output-node-input at {output_node_input_idx}"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description}; last value: {last!r}")


def _retry_on_role_propagation(fn, *, timeout_s: float = 90.0, interval_s: float = 5.0):
    """Retry a call that depends on a just-created IAM role being assumable/queryable.

    IAM is eventually consistent; bedrock.amazonaws.com may not yet be able to
    assume (or bedrock-agent to validate) a role created seconds earlier.
    """
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - re-raised below if it never resolves
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code not in ("AccessDeniedException", "ValidationException"):
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"IAM role never propagated within {timeout_s}s: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
