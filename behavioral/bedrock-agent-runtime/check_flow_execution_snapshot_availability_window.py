"""flow-execution-snapshot-availability-window."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "flow-execution-snapshot-availability-window"
GROUP = "visibility-timeout-ttl"
SERVICES = ["bedrock-agent-runtime"]

# Provisions an IAM role, a Bedrock flow, a version and an alias, and runs one flow execution.
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetExecutionFlowSnapshot of a succeeded execution returns the flow id, version, execution role and
    both node names; for an execution that never existed it gets ResourceNotFoundException with the
    exact message."""
    runtime = ctx.client("bedrock-agent-runtime")
    control = ctx.client("bedrock-agent")
    iam = ctx.client("iam")

    role_arn = _create_flow_execution_role(ctx, iam)
    try:
        flow_id = _create_passthrough_flow(ctx, control, role_arn)
    except Exception as err:  # pragma: no cover - environment dependent
        code = getattr(err, "response", {}).get("Error", {}).get("Code")
        if code == "AccessDeniedException":
            raise AssertionError(
                "CreateFlow was denied access (Bedrock Agents API in "
                "account-wide maintenance/restricted mode for this account); "
                "enable Bedrock flows access to close this gap."
            )
        raise

    version = _prepare_and_version_flow(ctx, control, flow_id)
    alias_id = _create_flow_alias(ctx, control, flow_id, version)

    payload = ctx.unique_name("sim2real-flow-payload-")
    start = runtime.start_flow_execution(
        flowIdentifier=flow_id,
        flowAliasIdentifier=alias_id,
        inputs=[
            {
                "content": {"document": payload},
                "nodeName": "FlowInputNode",
                "nodeOutputName": "document",
            }
        ],
    )
    execution_id = start["executionArn"].rsplit("/", 1)[-1]

    status = _poll_until(
        lambda: runtime.get_flow_execution(
            flowIdentifier=flow_id,
            flowAliasIdentifier=alias_id,
            executionIdentifier=execution_id,
        )["status"],
        lambda s: s != "Running",
        timeout_s=120,
        interval_s=2,
    )
    assert status == "Succeeded", f"expected trivial passthrough flow to succeed, got {status}"

    snapshot = runtime.get_execution_flow_snapshot(
        flowIdentifier=flow_id,
        flowAliasIdentifier=alias_id,
        executionIdentifier=execution_id,
    )
    assert snapshot["flowIdentifier"] == flow_id, snapshot
    assert snapshot["flowVersion"] == version, snapshot
    assert snapshot["executionRoleArn"] == role_arn, snapshot
    assert "FlowInputNode" in snapshot["definition"], (
        f"expected the captured snapshot definition to include FlowInputNode, got {snapshot['definition']!r}"
    )
    assert "FlowOutputNode" in snapshot["definition"], (
        f"expected the captured snapshot definition to include FlowOutputNode, got {snapshot['definition']!r}"
    )

    # Otherwise (an execution that never existed): ResourceNotFoundException.
    bogus_execution_id = str(uuid.uuid4())
    code, message = _error(
        lambda: runtime.get_execution_flow_snapshot(
            flowIdentifier=flow_id,
            flowAliasIdentifier=alias_id,
            executionIdentifier=bogus_execution_id,
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = "Resource not found, type: FlowExecution"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn):
    """Call fn() and return its error (code, message); raise AssertionError if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected GetExecutionFlowSnapshot on a never-existed executionIdentifier to be "
        f"rejected, but it SUCCEEDED and returned {result!r}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFoundException"):
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    return value


def _create_flow_execution_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-flow-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    return role_arn


def _create_passthrough_flow(ctx, control, role_arn: str) -> str:
    flow_name = ctx.unique_name("sim2real-flow-")
    definition = {
        "nodes": [
            {
                "type": "Input",
                "name": "FlowInputNode",
                "outputs": [{"name": "document", "type": "String"}],
            },
            {
                "type": "Output",
                "name": "FlowOutputNode",
                "inputs": [
                    {"name": "document", "type": "String", "expression": "$.data"}
                ],
            },
        ],
        "connections": [
            {
                "name": "FlowInputNodeFlowOutputNode",
                "source": "FlowInputNode",
                "target": "FlowOutputNode",
                "type": "Data",
                "configuration": {
                    "data": {"sourceOutput": "document", "targetInput": "document"}
                },
            }
        ],
    }

    # IAM trust-policy propagation is eventually consistent; retry CreateFlow
    # for a bounded window rather than sleeping a fixed duration up front.
    deadline = time.monotonic() + 60
    resp = None
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = control.create_flow(
                name=flow_name,
                executionRoleArn=role_arn,
                definition=definition,
                tags={"sim2real": CHECK},
            )
            break
        except Exception as err:
            last_err = err
            time.sleep(3)
    if resp is None:
        raise last_err

    flow_id = resp["id"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: control.delete_flow(flowIdentifier=flow_id, skipResourceInUseCheck=True)
        )
    )
    return flow_id


def _prepare_and_version_flow(ctx, control, flow_id: str) -> str:
    control.prepare_flow(flowIdentifier=flow_id)
    status = _poll_until(
        lambda: control.get_flow(flowIdentifier=flow_id)["status"],
        lambda s: s in ("Prepared", "Failed"),
        timeout_s=60,
        interval_s=2,
    )
    assert status == "Prepared", f"flow preparation did not succeed, status={status}"

    version_resp = control.create_flow_version(flowIdentifier=flow_id)
    return version_resp["version"]


def _create_flow_alias(ctx, control, flow_id: str, version: str) -> str:
    alias_name = ctx.unique_name("sim2real-flow-alias-")
    resp = control.create_flow_alias(
        flowIdentifier=flow_id,
        name=alias_name,
        routingConfiguration=[{"flowVersion": version}],
        tags={"sim2real": CHECK},
    )
    alias_id = resp["id"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: control.delete_flow_alias(flowIdentifier=flow_id, aliasIdentifier=alias_id)
        )
    )
    return alias_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
