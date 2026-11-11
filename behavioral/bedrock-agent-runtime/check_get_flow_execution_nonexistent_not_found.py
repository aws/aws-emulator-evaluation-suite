"""get-flow-execution-nonexistent-not-found."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "get-flow-execution-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["bedrock-agent-runtime"]

_INPUT_NODE = "FlowInputNode"
_OUTPUT_NODE = "FlowOutputNode"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetFlowExecution on a real flow/alias/execution triple succeeds (positive
    control); on the same real flow/alias but a well-formed, never-created
    executionIdentifier it is rejected with ResourceNotFoundException."""
    iam = ctx.client("iam")
    agent = ctx.client("bedrock-agent")
    runtime = ctx.client("bedrock-agent-runtime")

    role_name = ctx.unique_name("sim2real-bar-getfe-role-")
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

    flow_name = ctx.unique_name("sim2real-bar-getfe-flow-")
    flow_id = _retry_on_role_propagation(
        lambda: agent.create_flow(name=flow_name, executionRoleArn=role_arn, definition=flow_def),
    )["id"]
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

    alias_name = ctx.unique_name("sim2real-bar-getfe-alias-")
    alias_id = agent.create_flow_alias(
        flowIdentifier=flow_id,
        name=alias_name,
        routingConfiguration=[{"flowVersion": version}],
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
                    "content": {"document": "hello-get-flow-execution"},
                }
            ],
        ),
    )["executionArn"]

    # Positive control: GetFlowExecution on the real, well-formed triple succeeds
    # and reflects the execution reaching a terminal state.
    control = _poll_until(
        lambda: runtime.get_flow_execution(
            flowIdentifier=flow_id, flowAliasIdentifier=alias_id, executionIdentifier=execution_arn
        ),
        lambda resp: resp["status"] in ("Succeeded", "Failed", "TimedOut", "Aborted"),
        timeout_s=60.0,
        interval_s=2.0,
        description="flow execution to reach a terminal status",
    )
    assert control["status"] == "Succeeded", f"expected control execution to succeed, got {control['status']}"
    assert control["executionArn"] == execution_arn, (
        f"expected control GetFlowExecution to reflect {execution_arn}, got {control.get('executionArn')}"
    )

    # Negative: break exactly one thing -- swap the real executionIdentifier for a
    # well-formed one that was never started, under the SAME real flow/alias that
    # the positive control just proved works. This isolates execution-level
    # not-found from flow- or alias-level not-found.
    bogus_execution_id = str(uuid.uuid4())
    code, message = _error(
        lambda: runtime.get_flow_execution(
            flowIdentifier=flow_id,
            flowAliasIdentifier=alias_id,
            executionIdentifier=bogus_execution_id,
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = "Resource not found, type: FlowExecution"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn) -> tuple[str, str | None]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
