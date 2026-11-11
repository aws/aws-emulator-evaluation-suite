"""flow-version-snapshots-definition-immutably."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "flow-version-snapshots-definition-immutably"
GROUP = "versioning"
SERVICES = ["bedrock-agent"]


def _definition(output_expression: str) -> dict:
    return {
        "nodes": [
            {"name": "FlowInputNode", "type": "Input", "outputs": [{"name": "document", "type": "String"}]},
            {
                "name": "FlowOutputNode",
                "type": "Output",
                "inputs": [{"name": "document", "type": "String", "expression": output_expression}],
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


def _output_expression(definition: dict) -> str:
    for node in definition["nodes"]:
        if node["type"] == "Output":
            return node["inputs"][0]["expression"]
    raise AssertionError(f"no Output node in definition: {definition!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateFlowVersion freezes the DRAFT definition (not just its description); a later
    UpdateFlow that changes the definition's own content does not mutate the numbered version."""
    role_arn = _create_flow_role(ctx)
    bedrock_agent = ctx.client("bedrock-agent")
    name = ctx.unique_name("sim2real-flow-")
    created = bedrock_agent.create_flow(
        name=name, executionRoleArn=role_arn, definition=_definition("$.data"), description="v1"
    )
    flow_id = created["id"]
    # Capture AWS's own normalized definition rather than the literal we sent: the service
    # renames auto-generated connection ids on the round trip, so a literal comparison would
    # fail even against a correct target.
    original_definition = created["definition"]
    original_expression = _output_expression(original_definition)
    ctx.on_cleanup(lambda: bedrock_agent.delete_flow(flowIdentifier=flow_id, skipResourceInUseCheck=True))

    bedrock_agent.prepare_flow(flowIdentifier=flow_id)
    _poll_until(
        lambda: bedrock_agent.get_flow(flowIdentifier=flow_id),
        lambda f: f["status"] not in ("Preparing", "NotPrepared"),
        timeout_s=90.0,
    )

    versioned = bedrock_agent.create_flow_version(flowIdentifier=flow_id, description="v1")
    version_number = versioned["version"]
    version_snapshot = bedrock_agent.get_flow_version(flowIdentifier=flow_id, flowVersion=version_number)
    assert version_snapshot["description"] == "v1", f"expected snapshot description 'v1', got {version_snapshot['description']!r}"
    assert version_snapshot["definition"] == original_definition, (
        f"snapshot definition must match the prepared DRAFT at CreateFlowVersion time: "
        f"expected {original_definition!r}, got {version_snapshot['definition']!r}"
    )
    ctx.on_cleanup(
        lambda: bedrock_agent.delete_flow_version(
            flowIdentifier=flow_id, flowVersion=version_number, skipResourceInUseCheck=True
        )
    )

    bedrock_agent.update_flow(
        flowIdentifier=flow_id,
        name=name,
        executionRoleArn=role_arn,
        description="v2-mutated",
        definition=_definition("$.result"),
    )

    draft_now = bedrock_agent.get_flow(flowIdentifier=flow_id)
    assert draft_now["description"] == "v2-mutated", f"expected DRAFT description 'v2-mutated', got {draft_now['description']!r}"
    draft_expression = _output_expression(draft_now["definition"])
    assert draft_expression == "$.result", f"DRAFT definition must reflect the UpdateFlow that just ran: got {draft_expression!r}"

    frozen = bedrock_agent.get_flow_version(flowIdentifier=flow_id, flowVersion=version_number)
    assert frozen["description"] == "v1", "numbered flow version must remain frozen after later DRAFT edits"
    frozen_expression = _output_expression(frozen["definition"])
    assert frozen_expression == original_expression, (
        f"numbered flow version's definition must remain frozen after later DRAFT edits: "
        f"expected {original_expression!r}, got {frozen_expression!r}"
    )


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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
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
