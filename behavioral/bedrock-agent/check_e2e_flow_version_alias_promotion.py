"""e2e-flow-version-alias-promotion."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-flow-version-alias-promotion"
GROUP = "ordering"
SERVICES = ["bedrock-agent"]

_DEFINITION = {
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
            "name": "InputToOutput",
            "type": "Data",
            "source": "FlowInputNode",
            "target": "FlowOutputNode",
            "configuration": {"data": {"sourceOutput": "document", "targetInput": "document"}},
        }
    ],
}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A flow is prepared, versioned twice, and its alias is repointed from the older to the newer version."""
    bedrock_agent = ctx.client("bedrock-agent")
    role_arn = _create_flow_role(ctx)

    flow_name = ctx.unique_name("sim2real-flowver-")
    flow_id = _create_flow_with_role_propagation_retry(
        ctx, name=flow_name, executionRoleArn=role_arn, definition=_DEFINITION
    )["id"]
    ctx.on_cleanup(lambda: _safe(lambda: bedrock_agent.delete_flow(flowIdentifier=flow_id)))

    bedrock_agent.prepare_flow(flowIdentifier=flow_id)
    status = _poll_flow_status(ctx, flow_id)
    assert status == "Prepared", f"expected Prepared after first PrepareFlow, got {status}"

    version_1 = bedrock_agent.create_flow_version(flowIdentifier=flow_id)["version"]
    ctx.on_cleanup(
        lambda: _safe(lambda: bedrock_agent.delete_flow_version(flowIdentifier=flow_id, flowVersion=version_1))
    )

    # Force a second DRAFT revision: any update flips status back to NotPrepared, requiring re-preparation.
    bedrock_agent.update_flow(
        flowIdentifier=flow_id,
        name=flow_name,
        executionRoleArn=role_arn,
        definition=_DEFINITION,
        description="second revision for a sim2real behavioral fidelity check",
    )
    bedrock_agent.prepare_flow(flowIdentifier=flow_id)
    status = _poll_flow_status(ctx, flow_id)
    assert status == "Prepared", f"expected Prepared after second PrepareFlow, got {status}"

    version_2 = bedrock_agent.create_flow_version(flowIdentifier=flow_id)["version"]
    ctx.on_cleanup(
        lambda: _safe(lambda: bedrock_agent.delete_flow_version(flowIdentifier=flow_id, flowVersion=version_2))
    )
    assert version_2 != version_1, "second CreateFlowVersion must snapshot a distinct version number"

    alias_name = ctx.unique_name("sim2real-flowver-alias-")
    alias_id = bedrock_agent.create_flow_alias(
        flowIdentifier=flow_id, name=alias_name, routingConfiguration=[{"flowVersion": version_1}]
    )["id"]
    ctx.on_cleanup(
        lambda: _safe(lambda: bedrock_agent.delete_flow_alias(flowIdentifier=flow_id, aliasIdentifier=alias_id))
    )

    before = bedrock_agent.get_flow_alias(flowIdentifier=flow_id, aliasIdentifier=alias_id)
    before_version = before["routingConfiguration"][0]["flowVersion"]
    assert before_version == version_1, f"expected alias to resolve to {version_1!r}, got {before_version!r}"

    bedrock_agent.update_flow_alias(
        flowIdentifier=flow_id,
        aliasIdentifier=alias_id,
        name=alias_name,
        routingConfiguration=[{"flowVersion": version_2}],
    )

    after = bedrock_agent.get_flow_alias(flowIdentifier=flow_id, aliasIdentifier=alias_id)
    assert after["routingConfiguration"][0]["flowVersion"] == version_2, (
        "alias must resolve to the newly promoted version, not the one it was created with"
    )


def _create_flow_role(ctx):
    import json

    iam = ctx.client("iam")
    sts = ctx.client("sts")
    identity = sts.get_caller_identity()
    account_id = identity["Account"]
    partition = identity["Arn"].split(":")[1]

    role_name = ctx.unique_name("sim2real-flowver-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {"aws:SourceArn": f"arn:{partition}:bedrock:{ctx.region}:{account_id}:flow/*"},
                },
            }
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    return role_arn


def _create_flow_with_role_propagation_retry(ctx, timeout_s=30.0, interval_s=3.0, **kwargs):
    # IAM role creation is eventually consistent; CreateFlow may reject the fresh
    # role's ARN for a few seconds after IAM returns it. Retry only on that
    # specific window instead of sleeping blind before the first attempt.
    bedrock_agent = ctx.client("bedrock-agent")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return bedrock_agent.create_flow(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _poll_flow_status(ctx, flow_id, timeout_s=120.0, interval_s=5.0):
    bedrock_agent = ctx.client("bedrock-agent")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = bedrock_agent.get_flow(flowIdentifier=flow_id)["status"]
        if status in ("Prepared", "Failed"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"flow {flow_id} did not reach a terminal status within {timeout_s}s; last status={status!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFoundException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
