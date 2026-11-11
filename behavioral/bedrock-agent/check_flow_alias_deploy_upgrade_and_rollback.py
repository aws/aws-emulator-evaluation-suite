"""flow-alias-deploy-upgrade-and-rollback."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "flow-alias-deploy-upgrade-and-rollback"
GROUP = "state-machine"
SERVICES = ["bedrock-agent"]

# Exercises the "deploy" life cycle on a Flow: a flow alias is the deployment unit that
# routes traffic to a specific numbered version. CreateFlowAlias performs the initial deploy;
# UpdateFlowAlias then redeploys (upgrade) the same alias onto a newer version, and finally
# rolls it back to the prior version -- across every deploy/rollback the alias id must stay
# stable and route to exactly one version.


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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateFlowAlias deploys an alias to a numbered version; UpdateFlowAlias then redeploys
    (upgrade) it to a newer version in place, and finally rolls it back to the prior version --
    same alias id throughout, exactly one active routing target at every step."""
    role_arn = _create_flow_role(ctx)
    bedrock_agent = ctx.client("bedrock-agent")
    name = ctx.unique_name("sim2real-flow-")
    flow_id = bedrock_agent.create_flow(
        name=name, executionRoleArn=role_arn, definition=_definition("$.data"),
        tags={"sim2real-check": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: bedrock_agent.delete_flow(flowIdentifier=flow_id, skipResourceInUseCheck=True))

    bedrock_agent.prepare_flow(flowIdentifier=flow_id)
    prepared_1 = _poll_until(
        lambda: bedrock_agent.get_flow(flowIdentifier=flow_id),
        lambda f: f["status"] not in ("Preparing", "NotPrepared"),
        timeout_s=90.0,
    )
    assert prepared_1["status"] == "Prepared", f"expected Prepared after first PrepareFlow, got {prepared_1['status']}"
    version_1 = bedrock_agent.create_flow_version(flowIdentifier=flow_id)["version"]
    ctx.on_cleanup(
        lambda: bedrock_agent.delete_flow_version(flowIdentifier=flow_id, flowVersion=version_1, skipResourceInUseCheck=True)
    )

    alias_name = ctx.unique_name("sim2real-flow-alias-")
    alias = bedrock_agent.create_flow_alias(
        flowIdentifier=flow_id, name=alias_name, routingConfiguration=[{"flowVersion": version_1}],
        tags={"sim2real-check": CHECK},
    )
    alias_id = alias["id"]
    ctx.on_cleanup(lambda: bedrock_agent.delete_flow_alias(flowIdentifier=flow_id, aliasIdentifier=alias_id))
    assert alias["routingConfiguration"][0]["flowVersion"] == version_1, (
        f"CreateFlowAlias response expected routing to {version_1}, "
        f"got {alias['routingConfiguration'][0]['flowVersion']}"
    )

    fetched = bedrock_agent.get_flow_alias(flowIdentifier=flow_id, aliasIdentifier=alias_id)
    assert fetched["routingConfiguration"][0]["flowVersion"] == version_1, (
        f"GetFlowAlias expected routing to {version_1}, got {fetched['routingConfiguration'][0]['flowVersion']}"
    )

    # Deploy a second version, then redeploy the *same* alias onto it.
    bedrock_agent.update_flow(
        flowIdentifier=flow_id, name=name, executionRoleArn=role_arn, definition=_definition("$.data"),
        description="v2",
    )
    bedrock_agent.prepare_flow(flowIdentifier=flow_id)
    prepared_2 = _poll_until(
        lambda: bedrock_agent.get_flow(flowIdentifier=flow_id),
        lambda f: f["status"] not in ("Preparing", "NotPrepared"),
        timeout_s=90.0,
    )
    assert prepared_2["status"] == "Prepared", f"expected Prepared after second PrepareFlow, got {prepared_2['status']}"
    version_2 = bedrock_agent.create_flow_version(flowIdentifier=flow_id)["version"]
    assert version_2 != version_1, f"second CreateFlowVersion must snapshot a distinct version, got {version_2} twice"
    ctx.on_cleanup(
        lambda: bedrock_agent.delete_flow_version(flowIdentifier=flow_id, flowVersion=version_2, skipResourceInUseCheck=True)
    )

    redeployed = bedrock_agent.update_flow_alias(
        flowIdentifier=flow_id, aliasIdentifier=alias_id, name=alias_name,
        routingConfiguration=[{"flowVersion": version_2}],
    )
    assert redeployed["id"] == alias_id, "redeploying must repoint the existing alias, not create a new one"
    assert redeployed["routingConfiguration"][0]["flowVersion"] == version_2, (
        f"UpdateFlowAlias response expected routing to {version_2}, "
        f"got {redeployed['routingConfiguration'][0]['flowVersion']}"
    )

    refetched = bedrock_agent.get_flow_alias(flowIdentifier=flow_id, aliasIdentifier=alias_id)
    assert refetched["routingConfiguration"][0]["flowVersion"] == version_2, "alias must now route to the redeployed version"

    # Rollback deploy: same alias id, back to v1 -- v1 must still be fully intact (immutable
    # snapshot, never mutated by the intervening v2 deploy).
    rolled_back = bedrock_agent.update_flow_alias(
        flowIdentifier=flow_id, aliasIdentifier=alias_id, name=alias_name,
        routingConfiguration=[{"flowVersion": version_1}],
    )
    assert rolled_back["id"] == alias_id, "a rollback deploy must repoint the existing alias, not create a new one"
    assert rolled_back["routingConfiguration"][0]["flowVersion"] == version_1, (
        f"UpdateFlowAlias rollback expected routing to {version_1}, "
        f"got {rolled_back['routingConfiguration'][0]['flowVersion']}"
    )

    after_rollback = bedrock_agent.get_flow_alias(flowIdentifier=flow_id, aliasIdentifier=alias_id)
    assert after_rollback["routingConfiguration"][0]["flowVersion"] == version_1, "alias must route to the rolled-back version"
    assert len(after_rollback["routingConfiguration"]) == 1, "a rollback deploy must not leave a stale second routing entry"


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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
