"""flow-lifecycle-draft-version-alias."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "flow-lifecycle-draft-version-alias"
GROUP = "state-machine"
SERVICES = ["bedrock-agent"]

# Minimal valid flow: an Input node feeding straight into an Output node.
_DEFINITION = {
    "nodes": [
        {
            "name": "FlowInputNode",
            "type": "Input",
            "outputs": [{"name": "document", "type": "String"}],
        },
        {
            "name": "FlowOutputNode",
            "type": "Output",
            "inputs": [
                {"name": "document", "type": "String", "expression": "$.data"}
            ],
        },
    ],
    "connections": [
        {
            "type": "Data",
            "name": "InputToOutput",
            "source": "FlowInputNode",
            "target": "FlowOutputNode",
            "configuration": {
                "data": {"sourceOutput": "document", "targetInput": "document"}
            },
        }
    ],
}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Flow progresses NotPrepared->Prepared->numbered version->alias, and full
    teardown (alias, version, flow) makes GetFlow return ResourceNotFoundException."""
    bedrock = ctx.client("bedrock-agent")
    role_arn = _create_flow_execution_role(ctx)

    created = _create_flow_with_role_propagation_retry(
        ctx,
        name=ctx.unique_name("sim2real-flow-"),
        executionRoleArn=role_arn,
        definition=_DEFINITION,
    )
    flow_id = created["id"]
    assert created["status"] == "NotPrepared", f"expected NotPrepared on create, got {created['status']!r}"
    assert created["version"] == "DRAFT", f"expected version DRAFT on create, got {created['version']!r}"
    ctx.on_cleanup(lambda: _best_effort_delete_flow(bedrock, flow_id))

    _prepare_flow_with_role_propagation_retry(ctx, flow_id)
    status = _poll_until(
        lambda: bedrock.get_flow(flowIdentifier=flow_id)["status"],
        lambda s: s in ("Prepared", "Failed"),
        timeout_s=60,
    )
    assert status == "Prepared", f"expected Prepared, got {status}"

    version_resp = bedrock.create_flow_version(flowIdentifier=flow_id)
    version = version_resp["version"]
    assert version != "DRAFT" and version.isdigit(), f"expected a numeric version, got {version!r}"

    alias_resp = bedrock.create_flow_alias(
        flowIdentifier=flow_id,
        name=ctx.unique_name("sim2real-flow-alias-"),
        routingConfiguration=[{"flowVersion": version}],
    )
    alias_id = alias_resp["id"]
    got_alias = bedrock.get_flow_alias(flowIdentifier=flow_id, aliasIdentifier=alias_id)
    assert got_alias["routingConfiguration"][0]["flowVersion"] == version, (
        f"expected alias to route to version {version!r}, got {got_alias['routingConfiguration']!r}"
    )

    bedrock.delete_flow_alias(flowIdentifier=flow_id, aliasIdentifier=alias_id)
    code, message = _error(
        lambda: bedrock.get_flow_alias(flowIdentifier=flow_id, aliasIdentifier=alias_id)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException reading deleted alias, got {code!r}"
    assert message == _not_found("GetFlowAlias", "FlowAlias"), message
    redelete_code, message = _error(
        lambda: bedrock.delete_flow_alias(flowIdentifier=flow_id, aliasIdentifier=alias_id)
    )
    assert redelete_code == "ResourceNotFoundException", (
        f"expected re-deleting the same alias to fail with ResourceNotFoundException, got {redelete_code!r}"
    )
    assert message == _not_found("DeleteFlowAlias", "FlowAlias"), message

    bedrock.delete_flow_version(flowIdentifier=flow_id, flowVersion=version)
    code, message = _error(
        lambda: bedrock.get_flow_version(flowIdentifier=flow_id, flowVersion=version)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException reading deleted version, got {code!r}"
    assert message == _not_found("GetFlowVersion", "FlowVersion"), message
    redelete_code, message = _error(
        lambda: bedrock.delete_flow_version(flowIdentifier=flow_id, flowVersion=version)
    )
    assert redelete_code == "ResourceNotFoundException", (
        f"expected re-deleting the same version to fail with ResourceNotFoundException, got {redelete_code!r}"
    )
    assert message == _not_found("DeleteFlowVersion", "FlowVersion"), message

    bedrock.delete_flow(flowIdentifier=flow_id)
    code, message = _poll_error(lambda: bedrock.get_flow(flowIdentifier=flow_id), timeout_s=30)
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException reading deleted flow, got {code!r}"
    assert message == _not_found("GetFlow", "Flow"), message
    redelete_code, message = _error(lambda: bedrock.delete_flow(flowIdentifier=flow_id))
    assert redelete_code == "ResourceNotFoundException", (
        f"expected re-deleting the same flow to fail with ResourceNotFoundException, got {redelete_code!r}"
    )
    assert message == _not_found("DeleteFlow", "Flow"), message


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


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


def _best_effort_delete_flow(bedrock, flow_id):
    try:
        bedrock.delete_flow(flowIdentifier=flow_id, skipResourceInUseCheck=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_flow_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-bedrock-flow-role-")
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_flow_with_role_propagation_retry(ctx, **kwargs):
    bedrock = ctx.client("bedrock-agent")
    deadline = time.monotonic() + 30.0
    while True:
        try:
            return bedrock.create_flow(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException") and time.monotonic() < deadline:
                time.sleep(3.0)
                continue
            raise


def _prepare_flow_with_role_propagation_retry(ctx, flow_id, timeout_s=30.0, interval_s=3.0):
    bedrock = ctx.client("bedrock-agent")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            bedrock.prepare_flow(flowIdentifier=flow_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "AccessDeniedException" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
