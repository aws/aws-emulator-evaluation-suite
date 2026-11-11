"""flow-definition-representation-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "flow-definition-representation-round-trip"
GROUP = "state-machine"
SERVICES = ["bedrock-agent"]

# Exercises representation fidelity (data-plane depth) on Flow: GetFlow and GetFlowVersion
# must echo back the *exact* submitted definition structurally (node names/types, connection
# wiring) -- an emulator that only stores a coarse summary would fail this depth check.

_DEFINITION = {
    "nodes": [
        {"name": "FlowInputNode", "type": "Input", "outputs": [{"name": "document", "type": "String"}]},
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
    """A freshly created flow's DRAFT, and its later frozen numbered version, both echo back the
    exact node/connection structure that was submitted at create time."""
    role_arn = _create_flow_role(ctx)
    bedrock_agent = ctx.client("bedrock-agent")
    name = ctx.unique_name("sim2real-flow-")
    created = bedrock_agent.create_flow(
        name=name, executionRoleArn=role_arn, definition=_DEFINITION, tags={"sim2real": "behavioral"}
    )
    flow_id = created["id"]
    ctx.on_cleanup(lambda: bedrock_agent.delete_flow(flowIdentifier=flow_id, skipResourceInUseCheck=True))

    draft = bedrock_agent.get_flow(flowIdentifier=flow_id)
    draft_nodes = {n["name"]: n["type"] for n in draft["definition"]["nodes"]}
    assert draft_nodes == {"FlowInputNode": "Input", "FlowOutputNode": "Output"}, draft_nodes
    draft_connections = [(c["source"], c["target"], c["type"]) for c in draft["definition"]["connections"]]
    assert draft_connections == [("FlowInputNode", "FlowOutputNode", "Data")], draft_connections

    bedrock_agent.prepare_flow(flowIdentifier=flow_id)
    _poll_until(
        lambda: bedrock_agent.get_flow(flowIdentifier=flow_id),
        lambda f: f["status"] not in ("Preparing", "NotPrepared"),
        timeout_s=90.0,
    )
    version = bedrock_agent.create_flow_version(flowIdentifier=flow_id)["version"]
    ctx.on_cleanup(
        lambda: bedrock_agent.delete_flow_version(flowIdentifier=flow_id, flowVersion=version, skipResourceInUseCheck=True)
    )

    versioned = bedrock_agent.get_flow_version(flowIdentifier=flow_id, flowVersion=version)
    versioned_nodes = {n["name"]: n["type"] for n in versioned["definition"]["nodes"]}
    assert versioned_nodes == draft_nodes, versioned_nodes
    versioned_connections = [(c["source"], c["target"], c["type"]) for c in versioned["definition"]["connections"]]
    assert versioned_connections == draft_connections, versioned_connections
    # The expression wiring on the Output node's input must also be preserved byte-for-byte.
    versioned_output = next(n for n in versioned["definition"]["nodes"] if n["name"] == "FlowOutputNode")
    expression = versioned_output["inputs"][0]["expression"]
    assert expression == "$.data", expression


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed={last!r}")


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
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
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
