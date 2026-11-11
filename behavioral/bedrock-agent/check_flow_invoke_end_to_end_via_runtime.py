"""flow-invoke-end-to-end-via-runtime."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "flow-invoke-end-to-end-via-runtime"
GROUP = "cross-service"
SERVICES = ["bedrock-agent"]

# The cross-service data-plane depth check uses a Flow: a pure passthrough
# Input->Output flow requires no foundation-model call (cheap, no billing), yet still proves the
# control-plane (CreateFlow/PrepareFlow/CreateFlowAlias) and data-plane (InvokeFlow) are wired
# together correctly -- an emulator that fakes the control plane but cannot really route flow
# executions would fail here, unlike a smoke test that only checks CREATE/DESCRIBE.

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


@tags("axis:happy-path", "cap:c3", "cap:c4", "cap:c6", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A prepared flow+alias actually routes InvokeFlow input through to the Output node on the
    bedrock-agent-runtime data plane, echoing the exact payload that was submitted."""
    role_arn = _create_flow_role(ctx)
    bedrock_agent = ctx.client("bedrock-agent")
    name = ctx.unique_name("sim2real-flow-")
    flow_id = bedrock_agent.create_flow(
        name=name, executionRoleArn=role_arn, definition=_DEFINITION, tags={"sim2real-check": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: bedrock_agent.delete_flow(flowIdentifier=flow_id, skipResourceInUseCheck=True))

    bedrock_agent.prepare_flow(flowIdentifier=flow_id)
    _poll_until(
        lambda: bedrock_agent.get_flow(flowIdentifier=flow_id),
        lambda f: f["status"] not in ("Preparing", "NotPrepared"),
        timeout_s=90.0,
    )
    version = bedrock_agent.create_flow_version(flowIdentifier=flow_id)["version"]
    ctx.on_cleanup(
        lambda: bedrock_agent.delete_flow_version(flowIdentifier=flow_id, flowVersion=version, skipResourceInUseCheck=True)
    )

    alias_name = ctx.unique_name("sim2real-flow-alias-")
    alias_id = bedrock_agent.create_flow_alias(
        flowIdentifier=flow_id, name=alias_name, routingConfiguration=[{"flowVersion": version}]
    )["id"]
    ctx.on_cleanup(lambda: bedrock_agent.delete_flow_alias(flowIdentifier=flow_id, aliasIdentifier=alias_id))

    runtime = ctx.client("bedrock-agent-runtime")
    marker = ctx.unique_name("sim2real-flow-payload-")
    response = _invoke_flow_with_retry(
        runtime,
        flowIdentifier=flow_id,
        flowAliasIdentifier=alias_id,
        inputs=[{"content": {"document": marker}, "nodeName": "FlowInputNode", "nodeOutputName": "document"}],
    )

    output_value = None
    completion_reason = None
    for event in response["responseStream"]:
        if "flowOutputEvent" in event:
            output_value = event["flowOutputEvent"]["content"]["document"]
        if "flowCompletionEvent" in event:
            completion_reason = event["flowCompletionEvent"]["completionReason"]

    assert output_value == marker, f"expected the flow to echo {marker!r} through Input->Output, got {output_value!r}"
    assert completion_reason == "SUCCESS", f"expected flowCompletionEvent.completionReason SUCCESS, got {completion_reason!r}"


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed={last!r}")


def _invoke_flow_with_retry(runtime, timeout_s=90.0, interval_s=5.0, **kwargs):
    """IAM role trust/permissions can take a few seconds to propagate; poll past transient AccessDenied."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return runtime.invoke_flow(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code != "AccessDeniedException":
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"invoke_flow never succeeded after IAM propagation wait: {last_err}")


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
