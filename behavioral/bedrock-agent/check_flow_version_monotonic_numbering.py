"""flow-version-monotonic-numbering."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "flow-version-monotonic-numbering"
GROUP = "ordering"
SERVICES = ["bedrock-agent"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Repeated CreateFlowVersion calls yield strictly increasing, contiguous version numbers,
    and ListFlowVersions lists exactly that set of numbered versions."""
    role_arn = _create_flow_execution_role(ctx)
    bedrock = ctx.client("bedrock-agent")

    flow = _create_flow_with_role_propagation_retry(
        ctx,
        name=ctx.unique_name("sim2real-flow-"),
        executionRoleArn=role_arn,
        definition=_passthrough_flow_definition(),
    )
    flow_id = flow["id"]
    ctx.on_cleanup(lambda: bedrock.delete_flow(flowIdentifier=flow_id, skipResourceInUseCheck=True))

    created_versions = []
    for _ in range(3):
        _prepare_flow_and_wait(ctx, flow_id)
        resp = bedrock.create_flow_version(flowIdentifier=flow_id)
        created_versions.append(resp["version"])

    numeric_versions = [int(v) for v in created_versions]
    assert numeric_versions == sorted(numeric_versions), f"versions not increasing: {created_versions}"
    assert len(set(numeric_versions)) == 3, f"duplicate version numbers: {created_versions}"
    assert numeric_versions == list(range(numeric_versions[0], numeric_versions[0] + 3)), (
        f"versions are not a contiguous increasing sequence: {created_versions}"
    )

    listed = bedrock.list_flow_versions(flowIdentifier=flow_id)["flowVersionSummaries"]
    listed_numeric = [int(v["version"]) for v in listed if v["version"] != "DRAFT"]
    # ListFlowVersions documents no order for flowVersionSummaries, so the versions compare sorted.
    assert sorted(listed_numeric) == numeric_versions, (
        f"ListFlowVersions lists {listed_numeric}, expected exactly the created {numeric_versions}"
    )


def _passthrough_flow_definition() -> dict:
    return {
        "nodes": [
            {
                "name": "FlowInputNode",
                "type": "Input",
                "outputs": [{"name": "document", "type": "String"}],
            },
            {
                "name": "FlowOutputNode",
                "type": "Output",
                "inputs": [{"name": "document", "type": "String", "expression": "$.data"}],
            },
        ],
        "connections": [
            {
                "type": "Data",
                "name": "FlowInputNodeToFlowOutputNode",
                "source": "FlowInputNode",
                "target": "FlowOutputNode",
                "configuration": {"data": {"sourceOutput": "document", "targetInput": "document"}},
            }
        ],
    }


def _create_flow_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-bedrock-flow-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {"aws:SourceArn": f"arn:aws:bedrock:{ctx.region}:{account_id}:flow/*"},
                },
            }
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_flow_with_role_propagation_retry(ctx, **kwargs) -> dict:
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


def _prepare_flow_and_wait(ctx, flow_id: str, timeout_s: float = 180.0, interval_s: float = 3.0) -> None:
    bedrock = ctx.client("bedrock-agent")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            bedrock.prepare_flow(flowIdentifier=flow_id)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "AccessDeniedException" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise
    while time.monotonic() < deadline:
        status = bedrock.get_flow(flowIdentifier=flow_id)["status"]
        if status == "Prepared":
            return
        if status == "Failed":
            raise AssertionError("flow preparation failed (status=Failed)")
        time.sleep(interval_s)
    raise AssertionError("flow did not reach Prepared status within timeout")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
