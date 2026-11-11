"""deploy-agent-alias-invoke-behaves."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "deploy-agent-alias-invoke-behaves"
GROUP = "state-machine"
SERVICES = ["bedrock-agent-runtime"]

# NOTE: Bedrock Agents (classic) is closed to new customers, so this exercises the same
# CFN-deploy-then-invoke-via-runtime contract on an AWS::Bedrock::Flow instead: a passthrough
# Input->Output flow needs no foundation-model call, yet still proves that a flow provisioned
# entirely through CloudFormation (not the raw API) is actually routable through InvokeFlow on
# the bedrock-agent-runtime data plane.
_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  FlowName:
    Type: String
Resources:
  FlowExecutionRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: bedrock.amazonaws.com
            Action: sts:AssumeRole
            Condition:
              StringEquals:
                aws:SourceAccount: !Ref AWS::AccountId
              ArnLike:
                aws:SourceArn: !Sub arn:aws:bedrock:${AWS::Region}:${AWS::AccountId}:flow/*
  FlowResource:
    Type: AWS::Bedrock::Flow
    Properties:
      Name: !Ref FlowName
      ExecutionRoleArn: !GetAtt FlowExecutionRole.Arn
      Definition:
        Nodes:
          - Name: FlowInputNode
            Type: Input
            Configuration:
              Input: {}
            Outputs:
              - Name: document
                Type: String
          - Name: FlowOutputNode
            Type: Output
            Configuration:
              Output: {}
            Inputs:
              - Name: document
                Type: String
                Expression: "$.data"
        Connections:
          - Name: InputToOutput
            Type: Data
            Source: FlowInputNode
            Target: FlowOutputNode
            Configuration:
              Data:
                SourceOutput: document
                TargetInput: document
Outputs:
  FlowId:
    Value: !GetAtt FlowResource.Id
  FlowArn:
    Value: !Ref FlowResource
""".strip()


@tags("axis:happy-path", "cap:c3", "cap:c6", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed Bedrock Flow actually routes InvokeFlow traffic through to its
    Output node on the bedrock-agent-runtime data plane, echoing the exact payload submitted."""
    outputs = _deploy_cfn(
        ctx,
        _TEMPLATE,
        params={"FlowName": ctx.unique_name("sim2real-cfnflow-")},
    )
    flow_id = outputs["FlowId"]

    bedrock_agent = ctx.client("bedrock-agent")
    # AWS::Bedrock::Flow prepares as part of stack creation (unlike the raw CreateFlow API,
    # which leaves a freshly created flow NotPrepared until an explicit PrepareFlow call).
    flow = bedrock_agent.get_flow(flowIdentifier=flow_id)
    assert flow["status"] == "Prepared", f"expected Prepared right after CFN deploy, got {flow['status']!r}"

    version = bedrock_agent.create_flow_version(flowIdentifier=flow_id)["version"]
    ctx.on_cleanup(
        lambda: bedrock_agent.delete_flow_version(
            flowIdentifier=flow_id, flowVersion=version, skipResourceInUseCheck=True
        )
    )
    alias_name = ctx.unique_name("sim2real-cfnalias-")
    alias_id = bedrock_agent.create_flow_alias(
        flowIdentifier=flow_id, name=alias_name, routingConfiguration=[{"flowVersion": version}]
    )["id"]
    ctx.on_cleanup(lambda: bedrock_agent.delete_flow_alias(flowIdentifier=flow_id, aliasIdentifier=alias_id))

    runtime = ctx.client("bedrock-agent-runtime")
    marker = ctx.unique_name("sim2real-payload-")
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

    assert output_value == marker, (
        f"expected the CFN-deployed flow to echo {marker!r} through Input->Output, got {output_value!r}"
    )
    assert completion_reason == "SUCCESS", f"expected flow completion SUCCESS, got {completion_reason!r}"


# ===== helpers =====
def _deploy_cfn(ctx, template_body: str, params: dict[str, str]) -> dict[str, str]:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-bedrock-flow-stack-")

    try:
        cfn.create_stack(
            StackName=stack_name,
            TemplateBody=template_body,
            Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in params.items()],
            Capabilities=["CAPABILITY_IAM"],
            OnFailure="DO_NOTHING",
        )
    except ClientError as e:
        raise AssertionError(f"CreateStack failed: {e}") from e

    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))

    waiter = cfn.get_waiter("stack_create_complete")
    try:
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    except WaiterError as e:
        try:
            events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
            reasons = " | ".join(
                ev.get("ResourceStatusReason", "")
                for ev in events
                if "FAILED" in ev.get("ResourceStatus", "")
            )
        except ClientError:
            reasons = str(e)
        raise AssertionError(f"stack {stack_name} failed to reach CREATE_COMPLETE: {reasons}") from e

    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _invoke_flow_with_retry(runtime, timeout_s: float = 90.0, interval_s: float = 5.0, **kwargs):
    """The CFN-created execution role's trust/permissions can take a few seconds to propagate;
    poll past transient AccessDenied rather than asserting on the first attempt."""
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


def _delete_stack(ctx, stack_name: str) -> None:
    # DeleteStack is a no-op on a stack that is already gone, and the waiter treats a missing stack as
    # deleted, so any error here (e.g. DELETE_FAILED) is a real teardown failure and propagates.
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
