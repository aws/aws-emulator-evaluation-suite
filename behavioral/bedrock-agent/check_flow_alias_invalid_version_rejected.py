"""flow-alias-invalid-version-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "flow-alias-invalid-version-rejected"
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


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateFlowAlias pointing at a flowVersion that was never snapshotted is rejected; a real version alias still succeeds."""
    role_arn = _create_flow_role(ctx)

    flow_id = _create_flow_with_role_propagation_retry(
        ctx, name=ctx.unique_name("sim2real-badflowalias-"), executionRoleArn=role_arn, definition=_DEFINITION
    )["id"]
    bedrock_agent = ctx.client("bedrock-agent")
    ctx.on_cleanup(lambda: _safe(lambda: bedrock_agent.delete_flow(flowIdentifier=flow_id)))

    bedrock_agent.prepare_flow(flowIdentifier=flow_id)
    status = _poll_flow_status(ctx, flow_id)
    assert status == "Prepared", f"expected flow to reach Prepared, got {status}"

    # Break exactly one thing: a numbered version that was never snapshotted via CreateFlowVersion.
    bogus_version = "999999"
    code, message = _error(
        lambda: bedrock_agent.create_flow_alias(
            flowIdentifier=flow_id,
            name=ctx.unique_name("sim2real-badflowalias-al-"),
            routingConfiguration=[{"flowVersion": bogus_version}],
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == (
        f"1 validation error detected: Value '{bogus_version}' at 'routingConfiguration.1.member.flowVersion' "
        "failed to satisfy constraint: Member must have length less than or equal to 5"
    ), message

    # The effect is absent: no alias exists for the flow at all yet.
    aliases = bedrock_agent.list_flow_aliases(flowIdentifier=flow_id)["flowAliasSummaries"]
    assert not any(
        a["routingConfiguration"] and a["routingConfiguration"][0].get("flowVersion") == bogus_version
        for a in aliases
    ), f"a bogus-version alias should not appear in list_flow_aliases, got {aliases}"

    # Positive control in the same file: an alias routed to a real, snapshotted version still succeeds.
    real_version = bedrock_agent.create_flow_version(flowIdentifier=flow_id)["version"]
    ctx.on_cleanup(
        lambda: _safe(lambda: bedrock_agent.delete_flow_version(flowIdentifier=flow_id, flowVersion=real_version))
    )
    alias_name = ctx.unique_name("sim2real-goodflowalias-")
    alias_id = bedrock_agent.create_flow_alias(
        flowIdentifier=flow_id, name=alias_name, routingConfiguration=[{"flowVersion": real_version}]
    )["id"]
    ctx.on_cleanup(
        lambda: _safe(lambda: bedrock_agent.delete_flow_alias(flowIdentifier=flow_id, aliasIdentifier=alias_id))
    )

    got = bedrock_agent.get_flow_alias(flowIdentifier=flow_id, aliasIdentifier=alias_id)
    assert got["routingConfiguration"][0]["flowVersion"] == real_version, (
        f"expected alias to route to {real_version}, got {got['routingConfiguration']}"
    )


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_flow_role(ctx):
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    identity = sts.get_caller_identity()
    account_id = identity["Account"]
    partition = identity["Arn"].split(":")[1]

    role_name = ctx.unique_name("sim2real-badflowalias-role-")
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
