"""update-prepared-flow-leaves-existing-alias-unaffected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "update-prepared-flow-leaves-existing-alias-unaffected"
GROUP = "state-machine"
SERVICES = ["bedrock-agent"]

# A flow has a DRAFT with a Prepared/NotPrepared status, frozen numbered versions, and aliases
# that route to one specific version.

_DEFINITION_V1 = {
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
# A real change to the DRAFT's wiring (not cosmetic metadata) -- the expression the Output node
# reads its input from changes from "$.data" to "$.result".
_DEFINITION_V2 = {
    "nodes": _DEFINITION_V1["nodes"][:1]
    + [
        {
            "name": "FlowOutputNode",
            "type": "Output",
            "inputs": [{"name": "document", "type": "String", "expression": "$.result"}],
        }
    ],
    "connections": _DEFINITION_V1["connections"],
}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateFlow on a prepared flow reverts its status to NotPrepared, while the existing flow version
    keeps the old wiring and the alias still routes to that version."""
    role_arn = _create_flow_role(ctx)
    bedrock_agent = ctx.client("bedrock-agent")
    name = ctx.unique_name("sim2real-flow-")

    created = bedrock_agent.create_flow(
        name=name, executionRoleArn=role_arn, definition=_DEFINITION_V1, tags={"sim2real": CHECK}
    )
    flow_id = created["id"]
    ctx.on_cleanup(lambda: bedrock_agent.delete_flow(flowIdentifier=flow_id, skipResourceInUseCheck=True))

    bedrock_agent.prepare_flow(flowIdentifier=flow_id)
    status = _wait_flow_status(ctx, flow_id, {"Prepared", "Failed"})
    assert status == "Prepared", f"flow failed to prepare: {status}"

    version = bedrock_agent.create_flow_version(flowIdentifier=flow_id)["version"]
    ctx.on_cleanup(
        lambda: bedrock_agent.delete_flow_version(flowIdentifier=flow_id, flowVersion=version, skipResourceInUseCheck=True)
    )

    alias_name = ctx.unique_name("sim2real-flowalias-")
    alias = bedrock_agent.create_flow_alias(
        flowIdentifier=flow_id,
        name=alias_name,
        routingConfiguration=[{"flowVersion": version}],
        tags={"sim2real": CHECK},
    )
    alias_id = alias["id"]
    ctx.on_cleanup(lambda: bedrock_agent.delete_flow_alias(flowIdentifier=flow_id, aliasIdentifier=alias_id))

    # Change the DRAFT wiring. This must invalidate the DRAFT's prepared state.
    bedrock_agent.update_flow(flowIdentifier=flow_id, name=name, executionRoleArn=role_arn, definition=_DEFINITION_V2)
    updated = bedrock_agent.get_flow(flowIdentifier=flow_id)
    assert updated["status"] == "NotPrepared", updated["status"]

    # The frozen version still reflects the wiring it snapshotted at creation time, not the
    # later DRAFT edit, and the alias routed to it is unaffected.
    still_version = bedrock_agent.get_flow_version(flowIdentifier=flow_id, flowVersion=version)
    still_output = next(n for n in still_version["definition"]["nodes"] if n["name"] == "FlowOutputNode")
    assert still_output["inputs"][0]["expression"] == "$.data", still_output["inputs"][0]["expression"]

    still_alias = bedrock_agent.get_flow_alias(flowIdentifier=flow_id, aliasIdentifier=alias_id)
    assert still_alias["routingConfiguration"][0]["flowVersion"] == version, still_alias["routingConfiguration"]


def _create_flow_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-bagt-flowrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-bagt-flowpol-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["bedrock:InvokeModel", "bedrock:GetFoundationModel"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _wait_flow_status(ctx, flow_id, targets, timeout_s=90.0, interval_s=3.0):
    bedrock_agent = ctx.client("bedrock-agent")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = bedrock_agent.get_flow(flowIdentifier=flow_id)["status"]
        if last in targets:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"flow {flow_id} status never reached {targets}, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
