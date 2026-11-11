"""flow-version-delete-in-use-by-alias-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "flow-version-delete-in-use-by-alias-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agent"]

# Exercises the in-use guard on a Flow *version* (narrower than deleting the whole flow):
# DeleteFlowVersion must be rejected while an alias still routes to that exact version number.

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


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteFlowVersion is rejected while an alias still references that version; deleting the
    alias first unblocks the version delete."""
    role_arn = _create_flow_role(ctx)
    bedrock_agent = ctx.client("bedrock-agent")
    name = ctx.unique_name("sim2real-flow-")
    flow_id = bedrock_agent.create_flow(
        name=name,
        executionRoleArn=role_arn,
        definition=_DEFINITION,
        tags={"sim2real-check": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: bedrock_agent.delete_flow(flowIdentifier=flow_id, skipResourceInUseCheck=True))

    bedrock_agent.prepare_flow(flowIdentifier=flow_id)
    prepared = _poll_until(
        lambda: bedrock_agent.get_flow(flowIdentifier=flow_id),
        lambda f: f["status"] not in ("Preparing", "NotPrepared"),
        timeout_s=90.0,
    )
    assert prepared["status"] == "Prepared", f"expected Prepared, got {prepared['status']}"
    version = bedrock_agent.create_flow_version(flowIdentifier=flow_id)["version"]

    def _cleanup_version():
        try:
            bedrock_agent.delete_flow_version(flowIdentifier=flow_id, flowVersion=version, skipResourceInUseCheck=True)
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_version)

    alias_name = ctx.unique_name("sim2real-flow-alias-")
    alias_id = bedrock_agent.create_flow_alias(
        flowIdentifier=flow_id, name=alias_name, routingConfiguration=[{"flowVersion": version}]
    )["id"]

    code, message = _error(lambda: bedrock_agent.delete_flow_version(flowIdentifier=flow_id, flowVersion=version))
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    assert message == (
        "Couldn't perform DeleteFlowVersion operation. The Flow that you specified is currently in use by the "
        f"following alias: {alias_id}. Retry your request after the alias has finished using the Flow."
    ), message

    still_present = bedrock_agent.get_flow_version(flowIdentifier=flow_id, flowVersion=version)
    assert still_present["version"] == version, (
        f"expected version {version} to still exist after the blocked delete, got {still_present['version']}"
    )

    bedrock_agent.delete_flow_alias(flowIdentifier=flow_id, aliasIdentifier=alias_id)
    # Identical to the blocked call above (no skipResourceInUseCheck): this is what proves removing
    # the alias — not a bypass flag — is what unblocks the delete.
    bedrock_agent.delete_flow_version(flowIdentifier=flow_id, flowVersion=version)

    code, message = _error(lambda: bedrock_agent.get_flow_version(flowIdentifier=flow_id, flowVersion=version))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == _not_found("GetFlowVersion", "FlowVersion"), message


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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
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
