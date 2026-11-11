"""create-flow-alias-conflicting-name-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "create-flow-alias-conflicting-name-rejected"
GROUP = "error-semantics"
SERVICES = ["bedrock-agent"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFlowAlias with a name that duplicates an existing alias on the same flow is
    rejected as the conflicting-name rejection class, and no second alias with that name is
    created."""
    bedrock_agent = ctx.client("bedrock-agent")
    role_arn = _create_flow_role(ctx)

    flow = bedrock_agent.create_flow(
        name=ctx.unique_name("sim2real-bflow-"),
        executionRoleArn=role_arn,
        definition=_passthrough_flow_definition(),
        tags={"sim2real-check": CHECK},
    )
    flow_id = flow["id"]
    ctx.on_cleanup(lambda: _safe(lambda: bedrock_agent.delete_flow(flowIdentifier=flow_id, skipResourceInUseCheck=True)))

    bedrock_agent.prepare_flow(flowIdentifier=flow_id)
    status = _wait_flow_status(ctx, flow_id, {"Prepared", "Failed"})
    assert status == "Prepared", status

    # A flow alias's routing configuration must point at a non-DRAFT (numbered) version,
    # so create one from the prepared DRAFT first.
    version = bedrock_agent.create_flow_version(flowIdentifier=flow_id)["version"]

    alias_name = ctx.unique_name("sim2real-bflow-alias-")
    alias = bedrock_agent.create_flow_alias(
        flowIdentifier=flow_id,
        name=alias_name,
        routingConfiguration=[{"flowVersion": version}],
        tags={"sim2real-check": CHECK},
    )
    alias_id = alias["id"]
    ctx.on_cleanup(
        lambda: _safe(lambda: bedrock_agent.delete_flow_alias(flowIdentifier=flow_id, aliasIdentifier=alias_id))
    )

    code, message = _error(
        lambda: bedrock_agent.create_flow_alias(
            flowIdentifier=flow_id, name=alias_name, routingConfiguration=[{"flowVersion": version}]
        )
    )
    assert code == "ConflictException", code
    assert message == (
        f"Couldn't perform CreateFlowAlias operation. The name {alias_name} already exists for id "
        f"{alias_id}. Retry your request with a different name."
    ), message

    # Effect absent: exactly one alias with that name exists, not two.
    aliases = bedrock_agent.list_flow_aliases(flowIdentifier=flow_id)["flowAliasSummaries"]
    assert len([a for a in aliases if a["name"] == alias_name]) == 1, aliases

    # Positive control: a distinct alias name on the same flow is accepted.
    other_name = ctx.unique_name("sim2real-bflow-alias2-")
    other_alias = bedrock_agent.create_flow_alias(
        flowIdentifier=flow_id,
        name=other_name,
        routingConfiguration=[{"flowVersion": version}],
        tags={"sim2real-check": CHECK},
    )
    other_alias_id = other_alias["id"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: bedrock_agent.delete_flow_alias(flowIdentifier=flow_id, aliasIdentifier=other_alias_id)
        )
    )
    # Listing is eventually consistent right after a create - poll for both aliases to show up
    # rather than asserting an exact count immediately.
    names_seen = _wait_for_alias_names(ctx, flow_id, {alias_name, other_name})
    assert {alias_name, other_name} <= names_seen, names_seen


from botocore.exceptions import ClientError  # noqa: E402


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_flow_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-bflow-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "bedrock.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _passthrough_flow_definition():
    return {
        "nodes": [
            {
                "name": "FlowInputNode",
                "type": "Input",
                "configuration": {"input": {}},
                "outputs": [{"name": "document", "type": "String"}],
            },
            {
                "name": "FlowOutputNode",
                "type": "Output",
                "configuration": {"output": {}},
                "inputs": [{"name": "document", "type": "String", "expression": "$.data"}],
            },
        ],
        "connections": [
            {
                "name": "FlowInputNodeToFlowOutputNode",
                "source": "FlowInputNode",
                "target": "FlowOutputNode",
                "type": "Data",
                "configuration": {"data": {"sourceOutput": "document", "targetInput": "document"}},
            }
        ],
    }


def _wait_flow_status(ctx, flow_id, targets, timeout_s=120.0, interval_s=3.0):
    bedrock_agent = ctx.client("bedrock-agent")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = bedrock_agent.get_flow(flowIdentifier=flow_id)["status"]
        if last in targets:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"flow {flow_id} status never reached {targets}, last={last}")


def _wait_for_alias_names(ctx, flow_id, expected_names, timeout_s=60.0, interval_s=3.0):
    bedrock_agent = ctx.client("bedrock-agent")
    deadline = time.monotonic() + timeout_s
    seen = set()
    while time.monotonic() < deadline:
        aliases = bedrock_agent.list_flow_aliases(flowIdentifier=flow_id)["flowAliasSummaries"]
        seen = {a["name"] for a in aliases}
        if expected_names <= seen:
            return seen
        time.sleep(interval_s)
    raise AssertionError(f"expected names {expected_names} never all seen within {timeout_s}s; last saw {seen}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
