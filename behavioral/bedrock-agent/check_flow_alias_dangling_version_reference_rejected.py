"""flow-alias-dangling-version-reference-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "flow-alias-dangling-version-reference-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agent"]

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


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateFlowAlias is rejected when routingConfiguration references a flow version that doesn't exist."""
    role_arn = _create_flow_role(ctx)
    bedrock_agent = ctx.client("bedrock-agent")
    name = ctx.unique_name("sim2real-flow-")
    flow_id = bedrock_agent.create_flow(name=name, executionRoleArn=role_arn, definition=_DEFINITION)["id"]
    ctx.on_cleanup(lambda: bedrock_agent.delete_flow(flowIdentifier=flow_id, skipResourceInUseCheck=True))

    bedrock_agent.prepare_flow(flowIdentifier=flow_id)
    _poll_until(
        lambda: bedrock_agent.get_flow(flowIdentifier=flow_id),
        lambda f: f["status"] not in ("Preparing", "NotPrepared"),
        timeout_s=90.0,
    )
    real_version = bedrock_agent.create_flow_version(flowIdentifier=flow_id)["version"]
    ctx.on_cleanup(
        lambda: bedrock_agent.delete_flow_version(
            flowIdentifier=flow_id, flowVersion=real_version, skipResourceInUseCheck=True
        )
    )

    alias_name = ctx.unique_name("sim2real-flow-alias-")
    code, message = _error(
        lambda: bedrock_agent.create_flow_alias(
            flowIdentifier=flow_id,
            name=alias_name,
            routingConfiguration=[{"flowVersion": "999"}],
        )
    )
    assert code == "ResourceNotFoundException", code
    assert message == _not_found("CreateFlowAlias", "FlowVersion"), message

    aliases_after_reject = bedrock_agent.list_flow_aliases(flowIdentifier=flow_id)["flowAliasSummaries"]
    assert all(a["name"] != alias_name for a in aliases_after_reject), (
        f"rejected alias {alias_name!r} unexpectedly appeared in list_flow_aliases: {aliases_after_reject}"
    )

    created_alias = bedrock_agent.create_flow_alias(
        flowIdentifier=flow_id,
        name=alias_name,
        routingConfiguration=[{"flowVersion": real_version}],
    )
    alias_id = created_alias["id"]
    ctx.on_cleanup(lambda: bedrock_agent.delete_flow_alias(flowIdentifier=flow_id, aliasIdentifier=alias_id))

    fetched_alias = bedrock_agent.get_flow_alias(flowIdentifier=flow_id, aliasIdentifier=alias_id)
    assert fetched_alias["routingConfiguration"][0]["flowVersion"] == real_version, (
        f"expected routingConfiguration.flowVersion={real_version!r}, "
        f"got {fetched_alias['routingConfiguration']!r} from independent get_flow_alias read"
    )


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _not_found(operation, resource_type):
    return (
        f"Couldn't perform {operation} operation. Failed to retrieve resource type {resource_type} "
        "because it doesn't exist. Check the resource ID and retry your request."
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
