"""deploy-flow-cfn-behaves."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deploy-flow-cfn-behaves"
GROUP = "state-machine"
SERVICES = ["bedrock-agent"]

_TEMPLATE = """AWSTemplateFormatVersion: "2010-09-09"
Description: sim2real behavioral check - bedrock flow passthrough
Resources:
  FlowExecutionRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: __ROLE_NAME__
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: bedrock.amazonaws.com
            Action: sts:AssumeRole
            Condition:
              StringEquals:
                aws:SourceAccount: !Sub "${AWS::AccountId}"
              ArnLike:
                aws:SourceArn: !Sub "arn:${AWS::Partition}:bedrock:${AWS::Region}:${AWS::AccountId}:flow/*"
  FlowResource:
    Type: AWS::Bedrock::Flow
    Properties:
      Name: __FLOW_NAME__
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
"""

# The same definition, mirrored as the API-shaped (camelCase) dict for ValidateFlowDefinition.
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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed Flow validates, prepares, and its alias resolves a snapshotted version."""
    cfn = ctx.client("cloudformation")
    bedrock_agent = ctx.client("bedrock-agent")

    stack_name = ctx.unique_name("sim2real-bflow-cfn-")
    role_name = ctx.unique_name("sim2real-bflow-role-")
    flow_name = ctx.unique_name("sim2real-flow-")

    template = _TEMPLATE.replace("__ROLE_NAME__", role_name).replace("__FLOW_NAME__", flow_name)

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    _wait_stack_complete(ctx, stack_name, "CREATE_COMPLETE", {"ROLLBACK_COMPLETE", "CREATE_FAILED"})

    outputs = _stack_outputs(ctx, stack_name)
    flow_arn = outputs["FlowArn"]
    flow_id = outputs["FlowId"]

    # CloudFormation's AWS::Bedrock::Flow resource prepares the flow as part of stack creation,
    # so it is already Prepared by the time CREATE_COMPLETE is reached (unlike the raw API, where
    # a freshly created flow starts NotPrepared until an explicit PrepareFlow call).
    flow = bedrock_agent.get_flow(flowIdentifier=flow_id)
    assert flow["status"] == "Prepared", f"expected Prepared right after CFN deploy, got {flow['status']}"

    validation = bedrock_agent.validate_flow_definition(definition=_DEFINITION)
    errors = [v for v in validation["validations"] if v.get("severity") == "Error"]
    assert not errors, f"unexpected validation errors on a passthrough definition: {errors}"

    # PrepareFlow is idempotent on an already-Prepared flow: re-running it must still resolve to Prepared.
    bedrock_agent.prepare_flow(flowIdentifier=flow_id)
    prepared_status = _poll_flow_status(ctx, flow_id, timeout_s=180.0)
    assert prepared_status == "Prepared", f"flow never reached Prepared, last status={prepared_status}"

    alias_name = ctx.unique_name("sim2real-falias-")
    flow_version = bedrock_agent.create_flow_version(flowIdentifier=flow_id)["version"]
    ctx.on_cleanup(
        lambda: bedrock_agent.delete_flow_version(flowIdentifier=flow_id, flowVersion=flow_version)
    )
    alias = bedrock_agent.create_flow_alias(
        flowIdentifier=flow_id,
        name=alias_name,
        routingConfiguration=[{"flowVersion": flow_version}],
        tags={"sim2real": CHECK},
    )
    alias_id = alias["id"]
    ctx.on_cleanup(lambda: bedrock_agent.delete_flow_alias(flowIdentifier=flow_id, aliasIdentifier=alias_id))

    got_alias = bedrock_agent.get_flow_alias(flowIdentifier=flow_id, aliasIdentifier=alias_id)
    got_version = got_alias["routingConfiguration"][0]["flowVersion"]
    assert got_version == flow_version, f"alias {alias_id} routes to version {got_version!r}, expected {flow_version!r}"
    assert got_alias["flowId"] == flow_id, f"alias {alias_id} flowId {got_alias['flowId']!r} != expected {flow_id!r}"
    assert flow_arn.endswith(flow_id), f"stack output FlowArn {flow_arn!r} does not end with FlowId {flow_id!r}"


def _wait_stack_complete(ctx, stack_name, success_status, failure_statuses, timeout_s=900.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        last_status = stacks[0]["StackStatus"]
        if last_status == success_status:
            return
        if last_status in failure_statuses:
            raise AssertionError(f"stack {stack_name} reached {last_status}, expected {success_status}")
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} never reached {success_status}, last={last_status}")


def _stack_outputs(ctx, stack_name):
    cfn = ctx.client("cloudformation")
    stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    return {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])}


def _delete_stack(ctx, stack_name):
    from botocore.exceptions import ClientError

    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + 900.0
    last_status = None
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            if "does not exist" in str(exc):
                return
            raise
        if not stacks:
            return
        last_status = stacks[0]["StackStatus"]
        if last_status == "DELETE_COMPLETE":
            return
        if last_status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} failed to delete: DELETE_FAILED")
        time.sleep(10)
    raise AssertionError(f"stack {stack_name} did not reach DELETE_COMPLETE within 900s, last status={last_status}")


def _poll_flow_status(ctx, flow_id, timeout_s=180.0, interval_s=5.0):
    bedrock_agent = ctx.client("bedrock-agent")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = bedrock_agent.get_flow(flowIdentifier=flow_id)["status"]
        if status in ("Prepared", "Failed"):
            return status
        time.sleep(interval_s)
    return status


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
