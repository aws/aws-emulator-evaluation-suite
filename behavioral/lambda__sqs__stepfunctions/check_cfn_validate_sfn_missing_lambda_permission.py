"""cfn-validate-sfn-missing-lambda-permission."""

from __future__ import annotations

import json
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-validate-sfn-missing-lambda-permission"
GROUP = "overly-permissive"
SERVICES = ["lambda", "stepfunctions", "sqs"]

DEPLOYMENTS = Path(__file__).parent / "deployments"


def _expect_error(fn):
    """Call fn(); return the botocore Error dict. Raises if fn() unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"Expected a ClientError, but the call succeeded: {result!r}")


@tags(
    "cap:c1",
    "concern:representation",
    "concern:negative-classes",
    "plane:control",
    "axis:rejection",
)
def run(ctx) -> None:
    """ValidateTemplate accepts a template whose SFN role lacks lambda:InvokeFunction and reports
    the CAPABILITY_NAMED_IAM its named roles need with the exact reason, and rejects a template
    without Resources with ValidationError (exact message)."""
    template = """
AWSTemplateFormatVersion: '2010-09-09'
Description: SFN stack with missing lambda:InvokeFunction permission

Resources:
  ResultQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: !Sub 'sim2real-xsvc-noperm-q-${AWS::StackName}'

  LambdaRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub 'sim2real-xsvc-noperm-lrole-${AWS::StackName}'
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: LambdaPolicy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: '*'

  ProcessorFn:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Sub 'sim2real-xsvc-noperm-fn-${AWS::StackName}'
      Runtime: python3.11
      Handler: index.lambda_handler
      Role: !GetAtt LambdaRole.Arn
      Code:
        ZipFile: |
          def lambda_handler(event, context):
              return {'ok': True}

  SfnRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub 'sim2real-xsvc-noperm-sfnrole-${AWS::StackName}'
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: states.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: SfnPolicyNoLambda
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                Resource: '*'

  StateMachine:
    Type: AWS::StepFunctions::StateMachine
    Properties:
      StateMachineName: !Sub 'sim2real-xsvc-noperm-sm-${AWS::StackName}'
      RoleArn: !GetAtt SfnRole.Arn
      DefinitionString: !Sub |
        {
          "StartAt": "InvokeLambda",
          "States": {
            "InvokeLambda": {
              "Type": "Task",
              "Resource": "arn:aws:states:::lambda:invoke",
              "Parameters": {
                "FunctionName": "${ProcessorFn.Arn}",
                "Payload.$": "$"
              },
              "End": true
            }
          }
        }

Outputs:
  StateMachineArn:
    Value: !Ref StateMachine
  ResultQueueUrl:
    Value: !Ref ResultQueue
  FunctionArn:
    Value: !GetAtt ProcessorFn.Arn
"""

    cfn = ctx.client("cloudformation")

    # Positive control: the well-formed template validates, and CloudFormation's own computed
    # Capabilities/CapabilitiesReason -- not a string this file already wrote -- confirm it actually
    # parsed the two named IAM::Role resources.
    resp = cfn.validate_template(TemplateBody=template)
    assert resp.get("ResponseMetadata", {}).get("HTTPStatusCode") == 200, (
        f"Template validation failed: {resp}"
    )
    capabilities = resp.get("Capabilities", [])
    assert "CAPABILITY_NAMED_IAM" in capabilities, (
        f"Expected CAPABILITY_NAMED_IAM for the two named IAM roles, got: {capabilities}"
    )
    expected_reason = "The following resource(s) require capabilities: [AWS::IAM::Role]"
    assert resp.get("CapabilitiesReason") == expected_reason, (
        f"Expected CapabilitiesReason {expected_reason!r}, got: {resp.get('CapabilitiesReason')!r}"
    )

    # Negative control: a malformed sibling (no Resources section) is rejected with the specific
    # ValidationError, and the message names the missing section -- proving the validator inspects
    # structure rather than accepting any well-formed YAML/JSON.
    bad_template = json.dumps(
        {"AWSTemplateFormatVersion": "2010-09-09", "Description": "no resources"}
    )
    error = _expect_error(lambda: cfn.validate_template(TemplateBody=bad_template))
    assert error.get("Code") == "ValidationError", f"Expected ValidationError, got: {error}"
    expected_message = "Template format error: At least one Resources member must be defined."
    assert error.get("Message") == expected_message, (
        f"Expected the exact missing-Resources message {expected_message!r}, "
        f"got: {error.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
