"""flow-version-creation-without-prepare-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "flow-version-creation-without-prepare-rejected"
GROUP = "ordering"
SERVICES = ["bedrock-agent"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFlowVersion on a DRAFT that has never been Prepared is rejected with
    ConflictException, no version is created, and the same flow succeeds once Prepared
    (positive control)."""
    role_arn = _create_flow_execution_role(ctx)
    bedrock = ctx.client("bedrock-agent")

    flow = _create_flow_with_role_propagation_retry(
        ctx,
        name=ctx.unique_name("sim2real-flow-"),
        executionRoleArn=role_arn,
        definition=_passthrough_flow_definition(),
        tags={"sim2real:managed": "true"},
    )
    flow_id = flow["id"]
    ctx.on_cleanup(lambda: bedrock.delete_flow(flowIdentifier=flow_id, skipResourceInUseCheck=True))

    # Fresh DRAFT is NotPrepared -- creating a version now must be rejected.
    status = bedrock.get_flow(flowIdentifier=flow_id)["status"]
    assert status == "NotPrepared", f"expected fresh flow status NotPrepared, got {status}"
    listed_before = bedrock.list_flow_versions(flowIdentifier=flow_id)["flowVersionSummaries"]
    code, message = _error(lambda: bedrock.create_flow_version(flowIdentifier=flow_id))
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    assert message == (
        "Couldn't perform CreateFlowVersion operation. The resource that you specified is currently in "
        "status NotPrepared. Retry your request after the resource changes to a valid status."
    ), message

    # The effect must be absent: no NEW numbered version was created (a baseline DRAFT-only listing,
    # if any, is unaffected by the rejected call).
    listed = bedrock.list_flow_versions(flowIdentifier=flow_id)["flowVersionSummaries"]
    assert listed == listed_before, f"a version leaked despite the rejected call: {listed}"

    # Positive control: the identical call succeeds once the DRAFT is Prepared.
    _prepare_flow_and_wait(ctx, flow_id)
    resp = bedrock.create_flow_version(flowIdentifier=flow_id)
    assert resp["version"].isdigit(), f"expected a numeric version, got {resp['version']!r}"
    version = resp["version"]
    ctx.on_cleanup(
        lambda: bedrock.delete_flow_version(
            flowIdentifier=flow_id, flowVersion=version, skipResourceInUseCheck=True
        )
    )
    listed_after = bedrock.list_flow_versions(flowIdentifier=flow_id)["flowVersionSummaries"]
    versions_after = {v["version"] for v in listed_after}
    versions_before = {v["version"] for v in listed_before}
    assert resp["version"] in versions_after, f"new version missing from listing: {listed_after}"
    assert versions_after - versions_before == {resp["version"]}, (
        f"expected exactly one new version to appear: before={versions_before} after={versions_after}"
    )


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected ConflictException, but the call SUCCEEDED and returned {result!r}")


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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
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
