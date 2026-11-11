"""cfn-lambda-dynamodb-table-permissions-deployment."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lambda-dynamodb-table-permissions-deployment"
GROUP = "deployment-order"
SERVICES = ["dynamodb", "events", "lambda"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A deployed Lambda whose role grants DynamoDB CRUD on a deployed table can actually
    perform put/get/update/delete against that table end to end."""
    stack = _deploy_cfn(ctx, _TEMPLATE)
    function_name = stack["outputs"]["FunctionName"]
    table_name = stack["outputs"]["TableName"]
    lam = ctx.client("lambda")
    ddb = ctx.client("dynamodb")
    pk = ctx.unique_name("crud-")

    def _invoke(payload: dict[str, Any]) -> dict[str, Any]:
        resp = lam.invoke(FunctionName=function_name, Payload=json.dumps(payload).encode())
        body = json.loads(resp["Payload"].read())
        assert "FunctionError" not in resp, f"lambda invoke error: {body}"
        return body

    put_resp = _invoke({"action": "put", "id": pk, "value": "v1"})
    assert put_resp["ok"] is True, f"expected ok=True from put, got {put_resp!r}"

    get_resp = _invoke({"action": "get", "id": pk})
    assert get_resp["item"]["value"] == "v1", (
        f"expected value 'v1' after put, got {get_resp['item']!r}"
    )

    upd_resp = _invoke({"action": "update", "id": pk, "value": "v2"})
    assert upd_resp["ok"] is True, f"expected ok=True from update, got {upd_resp!r}"

    get_resp2 = _invoke({"action": "get", "id": pk})
    assert get_resp2["item"]["value"] == "v2", (
        f"expected value 'v2' after update, got {get_resp2['item']!r}"
    )

    del_resp = _invoke({"action": "delete", "id": pk})
    assert del_resp["ok"] is True, f"expected ok=True from delete, got {del_resp!r}"

    get_resp3 = _invoke({"action": "get", "id": pk})
    assert get_resp3["item"] is None, (
        f"expected no item after delete (via lambda), got {get_resp3['item']!r}"
    )

    # Cross-check the deleted state directly against DynamoDB too.
    direct = ddb.get_item(TableName=table_name, Key={"id": {"S": pk}})
    assert "Item" not in direct, (
        f"expected no Item in direct DynamoDB read after delete, got {direct.get('Item')!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


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
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return "GONE"

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
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
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Description: sim2real cfn-lambda-dynamodb-table-permissions-deployment
Resources:
  AppTable:
    Type: AWS::DynamoDB::Table
    Properties:
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions:
        - AttributeName: id
          AttributeType: S
      KeySchema:
        - AttributeName: id
          KeyType: HASH

  FunctionRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
      Policies:
        - PolicyName: ddb-crud
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - dynamodb:PutItem
                  - dynamodb:GetItem
                  - dynamodb:UpdateItem
                  - dynamodb:DeleteItem
                  - dynamodb:Query
                Resource: !GetAtt AppTable.Arn

  CrudFunction:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Role: !GetAtt FunctionRole.Arn
      Timeout: 10
      Environment:
        Variables:
          TABLE_NAME: !Ref AppTable
      Code:
        ZipFile: |
          import boto3, os
          def handler(event, context):
              table = boto3.resource('dynamodb').Table(os.environ['TABLE_NAME'])
              action = event['action']
              if action == 'put':
                  table.put_item(Item={'id': event['id'], 'value': event['value']})
                  return {'ok': True}
              if action == 'get':
                  resp = table.get_item(Key={'id': event['id']})
                  return {'item': resp.get('Item')}
              if action == 'update':
                  table.update_item(
                      Key={'id': event['id']},
                      UpdateExpression='SET #v = :v',
                      ExpressionAttributeNames={'#v': 'value'},
                      ExpressionAttributeValues={':v': event['value']},
                  )
                  return {'ok': True}
              if action == 'delete':
                  table.delete_item(Key={'id': event['id']})
                  return {'ok': True}
              raise ValueError('unknown action: ' + str(action))

Outputs:
  TableName:
    Value: !Ref AppTable
  FunctionName:
    Value: !Ref CrudFunction
"""

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
