"""flow-prepare-reaches-prepared."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "flow-prepare-reaches-prepared"
GROUP = "state-machine"
SERVICES = ["bedrock-agent"]

_MINIMAL_DEFINITION = {
    "nodes": [
        {
            "name": "FlowInputNode",
            "type": "Input",
            "outputs": [{"name": "document", "type": "String"}],
        },
        {
            "name": "FlowOutputNode",
            "type": "Output",
            "inputs": [{"name": "document", "type": "String", "expression": "$.data"}],
        },
    ],
    "connections": [
        {
            "name": "InputToOutput",
            "source": "FlowInputNode",
            "target": "FlowOutputNode",
            "type": "Data",
            "configuration": {"data": {"sourceOutput": "document", "targetInput": "document"}},
        }
    ],
}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PrepareFlow drives a well-formed DRAFT flow from NotPrepared through Preparing to Prepared."""
    role_arn = _create_flow_role(ctx)
    bedrock_agent = ctx.client("bedrock-agent")
    name = ctx.unique_name("sim2real-flow-")
    created = bedrock_agent.create_flow(
        name=name,
        executionRoleArn=role_arn,
        definition=_MINIMAL_DEFINITION,
        tags={"sim2real": CHECK},
    )
    flow_id = created["id"]
    ctx.on_cleanup(lambda: _best_effort_delete_flow(bedrock_agent, flow_id))
    assert created["status"] == "NotPrepared", created["status"]

    bedrock_agent.prepare_flow(flowIdentifier=flow_id)

    final = _poll_until(
        lambda: bedrock_agent.get_flow(flowIdentifier=flow_id),
        lambda f: f["status"] not in ("Preparing", "NotPrepared"),
        timeout_s=90.0,
    )
    assert final["status"] == "Prepared", final["status"]

    bedrock_agent.delete_flow(flowIdentifier=flow_id, skipResourceInUseCheck=True)
    code, message = _poll_error(lambda: bedrock_agent.get_flow(flowIdentifier=flow_id), timeout_s=30.0)
    assert code == "ResourceNotFoundException", code
    assert message == _not_found("GetFlow", "Flow"), message

    mutation_code, message = _error(lambda: bedrock_agent.prepare_flow(flowIdentifier=flow_id))
    assert mutation_code == "ResourceNotFoundException", mutation_code
    assert message == _not_found("PrepareFlow", "Flow"), message


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed={last!r}")


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _not_found(operation, resource_type):
    return (
        f"Couldn't perform {operation} operation. Failed to retrieve resource type {resource_type} "
        "because it doesn't exist. Check the resource ID and retry your request."
    )


def _poll_error(fn, timeout_s=30.0, interval_s=3.0):
    """Repeat fn() until it raises a ClientError; return that error (code, message). Raises when
    fn() still succeeds at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"call still SUCCEEDED after {timeout_s}s: {result!r}")
        time.sleep(interval_s)


def _best_effort_delete_flow(bedrock_agent, flow_id):
    try:
        bedrock_agent.delete_flow(flowIdentifier=flow_id, skipResourceInUseCheck=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_flow_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-flow-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "bedrock.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="bedrock-flow-permissions",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["bedrock:InvokeModel"], "Resource": "*"}]}
        ),
    )

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="bedrock-flow-permissions")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
