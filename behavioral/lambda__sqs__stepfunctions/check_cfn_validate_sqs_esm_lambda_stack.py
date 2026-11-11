"""cfn-validate-sqs-esm-lambda-stack."""

from __future__ import annotations

from pathlib import Path

from behavioral_harness import tags

CHECK = "cfn-validate-sqs-esm-lambda-stack"
GROUP = "deployment-order"
SERVICES = ["lambda", "stepfunctions", "sqs"]

DEPLOYMENTS = Path(__file__).parent / "deployments"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ValidateTemplate on the SQS, Lambda and event source mapping template requires exactly
    CAPABILITY_NAMED_IAM, attributes it to the AWS::IAM::Role resource and reports no parameters."""
    template = """
AWSTemplateFormatVersion: '2010-09-09'
Description: SQS + Lambda + ESM stack

Resources:
  SourceQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: !Sub 'sim2real-xsvc-src-${AWS::StackName}'

  ResultQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: !Sub 'sim2real-xsvc-res-${AWS::StackName}'

  LambdaRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub 'sim2real-xsvc-esm-lrole-${AWS::StackName}'
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
                  - sqs:ReceiveMessage
                  - sqs:DeleteMessage
                  - sqs:GetQueueAttributes
                Resource: !GetAtt SourceQueue.Arn
              - Effect: Allow
                Action:
                  - sqs:SendMessage
                Resource: !GetAtt ResultQueue.Arn
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: '*'

  LambdaFn:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Sub 'sim2real-xsvc-esm-fn-${AWS::StackName}'
      Runtime: python3.11
      Handler: index.lambda_handler
      Role: !GetAtt LambdaRole.Arn
      Environment:
        Variables:
          RESULT_QUEUE_URL: !Ref ResultQueue
      Code:
        ZipFile: |
          import boto3, os, json
          def lambda_handler(event, context):
              sqs = boto3.client('sqs')
              for record in event.get('Records', []):
                  sqs.send_message(QueueUrl=os.environ['RESULT_QUEUE_URL'], MessageBody=record['body'])
              return {'ok': True}

  ESM:
    Type: AWS::Lambda::EventSourceMapping
    Properties:
      EventSourceArn: !GetAtt SourceQueue.Arn
      FunctionName: !Ref LambdaFn
      BatchSize: 1
      Enabled: true

Outputs:
  SourceQueueUrl:
    Value: !Ref SourceQueue
  ResultQueueUrl:
    Value: !Ref ResultQueue
"""

    # ValidateTemplate parses the template without deploying it.
    cfn = ctx.client("cloudformation")
    resp = cfn.validate_template(TemplateBody=template)
    assert resp.get("ResponseMetadata", {}).get("HTTPStatusCode") == 200, (
        f"Template validation failed: {resp}"
    )
    assert "AWS::Lambda::EventSourceMapping" in template, (
        "EventSourceMapping resource not found in template"
    )
    assert "SourceQueueUrl" in template, "SourceQueueUrl output not declared"
    assert "ResultQueueUrl" in template, "ResultQueueUrl output not declared"
    assert "BatchSize: 1" in template or '"BatchSize": 1' in template, (
        "ESM BatchSize not set in template"
    )

    # LambdaRole sets an explicit RoleName, so CloudFormation's parser requires
    # CAPABILITY_NAMED_IAM and attributes that requirement to the AWS::IAM::Role resource.
    capabilities = resp.get("Capabilities", [])
    assert capabilities == ["CAPABILITY_NAMED_IAM"], (
        f"Expected CloudFormation to require exactly CAPABILITY_NAMED_IAM because LambdaRole sets "
        f"an explicit RoleName, got Capabilities={capabilities!r}"
    )
    reason = resp.get("CapabilitiesReason", "")
    assert "AWS::IAM::Role" in reason, (
        f"Expected CapabilitiesReason to attribute the capability to the AWS::IAM::Role resource "
        f"type, got: {reason!r}"
    )
    assert resp.get("Parameters", []) == [], (
        f"Expected CloudFormation to parse zero template Parameters, got: {resp.get('Parameters')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
