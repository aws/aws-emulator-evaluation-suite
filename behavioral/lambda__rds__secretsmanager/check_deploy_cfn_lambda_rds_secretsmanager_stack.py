"""deploy-cfn-lambda-rds-secretsmanager-stack."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-lambda-rds-secretsmanager-stack"
GROUP = "deployment-order"
SERVICES = ["lambda", "rds", "secretsmanager"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """CFN deploys an Aurora Serverless v2 cluster + a Secrets Manager secret + a Lambda whose
    role can read the secret and query the cluster over RDS Data API; the deployed Lambda must
    actually read the secret and execute a real SQL statement against the cluster post-deploy."""
    stack = _deploy_cfn(ctx, _TEMPLATE, timeout_s=1200.0)
    outputs = stack["outputs"]
    function_name = outputs["FunctionName"]

    lambda_client = ctx.client("lambda")

    def _invoke():
        resp = lambda_client.invoke(FunctionName=function_name, Payload=b"{}")
        payload = json.loads(resp["Payload"].read())
        return {"function_error": resp.get("FunctionError"), "payload": payload}

    result = _poll_until(
        _invoke,
        lambda r: r["function_error"] is None and r["payload"].get("ok") == 42,
        timeout_s=180.0,
        interval_s=10.0,
        description="lambda successfully reads secret and queries rds data api",
    )
    assert result["function_error"] is None, f"lambda invocation errored: {result}"
    assert result["payload"]["ok"] == 42, f"expected rds-data SELECT 41+1 == 42, got {result['payload']!r}"
    assert result["payload"]["username"] == "appadmin", (
        f"expected the templated secret username 'appadmin' read back through the lambda, "
        f"got {result['payload']!r}"
    )


_TEMPLATE = r"""
AWSTemplateFormatVersion: "2010-09-09"
Description: sim2real lambda + aurora serverless v2 (data api) + secretsmanager
Resources:
  AppSecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Description: sim2real db credentials
      GenerateSecretString:
        SecretStringTemplate: '{"username":"appadmin"}'
        GenerateStringKey: password
        ExcludeCharacters: '"@/'
        PasswordLength: 20
  DBCluster:
    Type: AWS::RDS::DBCluster
    Properties:
      Engine: aurora-mysql
      EngineVersion: "8.0"
      DatabaseName: appdb
      MasterUsername: !Sub "{{resolve:secretsmanager:${AppSecret}:SecretString:username}}"
      MasterUserPassword: !Sub "{{resolve:secretsmanager:${AppSecret}:SecretString:password}}"
      EnableHttpEndpoint: true
      ServerlessV2ScalingConfiguration:
        MinCapacity: 0.5
        MaxCapacity: 1
      BackupRetentionPeriod: 1
      StorageEncrypted: true
  DBInstance:
    Type: AWS::RDS::DBInstance
    Properties:
      Engine: aurora-mysql
      DBInstanceClass: db.serverless
      DBClusterIdentifier: !Ref DBCluster
      PubliclyAccessible: false
  SecretAttachment:
    Type: AWS::SecretsManager::SecretTargetAttachment
    Properties:
      SecretId: !Ref AppSecret
      TargetId: !Ref DBCluster
      TargetType: AWS::RDS::DBCluster
  LambdaExecutionRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal: {Service: lambda.amazonaws.com}
            Action: sts:AssumeRole
      Policies:
        - PolicyName: access
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action: secretsmanager:GetSecretValue
                Resource: !Ref AppSecret
              - Effect: Allow
                Action:
                  - rds-data:ExecuteStatement
                  - rds-data:BatchExecuteStatement
                Resource: !GetAtt DBCluster.DBClusterArn
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: "*"
  QueryFn:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Role: !GetAtt LambdaExecutionRole.Arn
      Timeout: 30
      Environment:
        Variables:
          SECRET_ARN: !Ref AppSecret
          CLUSTER_ARN: !GetAtt DBCluster.DBClusterArn
      Code:
        ZipFile: |
          import json, os, boto3

          def handler(event, context):
              sm = boto3.client("secretsmanager")
              secret = sm.get_secret_value(SecretId=os.environ["SECRET_ARN"])
              creds = json.loads(secret["SecretString"])
              rdsdata = boto3.client("rds-data")
              resp = rdsdata.execute_statement(
                  resourceArn=os.environ["CLUSTER_ARN"],
                  secretArn=os.environ["SECRET_ARN"],
                  database="appdb",
                  sql="SELECT 41 + 1 AS ok",
              )
              value = resp["records"][0][0]["longValue"]
              return {"username": creds.get("username"), "ok": value}
Outputs:
  SecretArn:
    Value: !Ref AppSecret
  ClusterArn:
    Value: !GetAtt DBCluster.DBClusterArn
  FunctionName:
    Value: !Ref QueryFn
"""


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
