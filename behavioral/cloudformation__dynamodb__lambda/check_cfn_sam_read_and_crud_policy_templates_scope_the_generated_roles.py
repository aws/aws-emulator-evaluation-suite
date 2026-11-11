"""cfn-sam-read-and-crud-policy-templates-scope-the-generated-roles."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-sam-read-and-crud-policy-templates-scope-the-generated-roles"

GROUP = "deployment-order"

SERVICES = ["cloudformation", "dynamodb", "lambda"]

#: Two serverless functions on one SimpleTable: Writer with DynamoDBCrudPolicy, Reader with
#: DynamoDBReadPolicy. Each policy template expands into its own role's inline policy.
_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: SAM policy templates scope access - CRUD writer, read-only reader

Parameters:
  TableName:
    Type: String
  WriterName:
    Type: String
  ReaderName:
    Type: String

Globals:
  Function:
    Runtime: python3.12
    Handler: index.handler
    Timeout: 30
    Environment:
      Variables:
        TABLE_NAME: !Ref TableName

Resources:
  Items:
    Type: AWS::Serverless::SimpleTable
    Properties:
      TableName: !Ref TableName
      PrimaryKey:
        Name: pk
        Type: String

  Writer:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: !Ref WriterName
      Policies:
        - DynamoDBCrudPolicy:
            TableName: !Ref Items
      InlineCode: |
        import os

        import boto3
        from botocore.exceptions import ClientError

        ddb = boto3.client('dynamodb')


        def handler(event, context):
            table = os.environ['TABLE_NAME']
            try:
                if event['op'] == 'put':
                    ddb.put_item(TableName=table, Item={'pk': {'S': event['pk']}, 'note': {'S': event['note']}})
                    return {'ok': True}
                item = ddb.get_item(TableName=table, Key={'pk': {'S': event['pk']}}, ConsistentRead=True)
                return {'ok': True, 'item': item.get('Item')}
            except ClientError as exc:
                return {'ok': False, 'code': exc.response['Error']['Code'],
                        'message': exc.response['Error']['Message']}

  Reader:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: !Ref ReaderName
      Policies:
        - DynamoDBReadPolicy:
            TableName: !Ref Items
      InlineCode: |
        import os

        import boto3
        from botocore.exceptions import ClientError

        ddb = boto3.client('dynamodb')


        def handler(event, context):
            table = os.environ['TABLE_NAME']
            try:
                if event['op'] == 'put':
                    ddb.put_item(TableName=table, Item={'pk': {'S': event['pk']}, 'note': {'S': event['note']}})
                    return {'ok': True}
                item = ddb.get_item(TableName=table, Key={'pk': {'S': event['pk']}}, ConsistentRead=True)
                return {'ok': True, 'item': item.get('Item')}
            except ClientError as exc:
                return {'ok': False, 'code': exc.response['Error']['Code'],
                        'message': exc.response['Error']['Message']}

Outputs:
  ReaderRoleArn:
    Value: !GetAtt ReaderRole.Arn
  WriterRoleArn:
    Value: !GetAtt WriterRole.Arn
"""


_READ_ACTIONS = {
    "dynamodb:GetItem", "dynamodb:Scan", "dynamodb:Query", "dynamodb:BatchGetItem", "dynamodb:DescribeTable",
}
_CRUD_ACTIONS = _READ_ACTIONS | {
    "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:BatchWriteItem",
    "dynamodb:ConditionCheckItem",
}


def _as_list(value):
    return value if isinstance(value, list) else [value]


def _inline_grants(iam, role_name):
    """{policy name: (sorted actions, sorted resources)} of a role's inline Allow statements."""
    grants = {}
    for policy_name in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
        doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)["PolicyDocument"]
        actions, resources = set(), set()
        for st in _as_list(doc["Statement"]):
            assert st["Effect"] == "Allow", f"{role_name}/{policy_name}: unexpected statement {st!r}"
            actions |= set(_as_list(st["Action"]))
            resources |= set(_as_list(st["Resource"]))
        grants[policy_name] = (sorted(actions), sorted(resources))
    return grants


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """SAM policy templates expand into each generated role: DynamoDBReadPolicy grants only the read
    actions and DynamoDBCrudPolicy the read and write actions, both on the table and its indexes;
    the CRUD function's item is read back through the read-only function and DynamoDB.
    """
    ddb = ctx.client("dynamodb")
    awslambda = ctx.client("lambda")
    iam = ctx.client("iam")
    table_name = _xname(ctx, "sam-scoped")
    writer, reader = _xname(ctx, "sam-w"), _xname(ctx, "sam-r")
    # Registered before the deploy, so LIFO runs them after the stack delete: a sweep for a table
    # the stack delete leaves behind, and the log groups Lambda creates outside the stack.
    ctx.on_cleanup(lambda: _delete_table_if_present(ddb, table_name))
    for fn in (writer, reader):
        ctx.on_cleanup(lambda f=fn: _delete_log_group_if_present(ctx, f"/aws/lambda/{f}"))

    result = _deploy_cfn(
        ctx, _TEMPLATE,
        parameters={"TableName": table_name, "WriterName": writer, "ReaderName": reader},
        capabilities=["CAPABILITY_AUTO_EXPAND", "CAPABILITY_IAM"], timeout_s=900.0,
    )
    outputs = _outputs(result)
    table_arn = ddb.describe_table(TableName=table_name)["Table"]["TableArn"]
    scope = sorted([table_arn, f"{table_arn}/index/*"])

    for fn, out_key, actions in ((reader, "ReaderRoleArn", _READ_ACTIONS), (writer, "WriterRoleArn", _CRUD_ACTIONS)):
        role_arn = outputs[out_key]
        configured = awslambda.get_function_configuration(FunctionName=fn)["Role"]
        assert configured == role_arn, f"{fn} must run as its generated role {role_arn!r}, got {configured!r}"
        role_name = role_arn.rsplit("/", 1)[-1]
        grants = _inline_grants(iam, role_name)
        assert list(grants.values()) == [(sorted(actions), scope)], (
            f"{role_name} must hold one inline policy granting exactly {sorted(actions)} on {scope}, got {grants!r}"
        )

    note = _xname(ctx, "note")
    assert _invoke_json(awslambda, writer, {"op": "put", "pk": "k1", "note": note}) == {"ok": True}
    read = _invoke_json(awslambda, reader, {"op": "get", "pk": "k1"})
    assert read == {"ok": True, "item": {"pk": {"S": "k1"}, "note": {"S": note}}}, (
        f"the read-only function must read the item the CRUD function wrote, got {read!r}"
    )
    stored = ddb.get_item(TableName=table_name, Key={"pk": {"S": "k1"}}, ConsistentRead=True)["Item"]
    assert stored == {"pk": {"S": "k1"}, "note": {"S": note}}, f"GetItem k1: got {stored!r}"


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _outputs(result: dict) -> dict:
    """Deployment results may nest outputs under 'outputs' or expose them flat."""
    return result.get("outputs", result)


def _poll_until(
    probe, predicate, *, timeout_s=40.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
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


def _invoke_json(awslambda, function_name: str, payload: dict) -> dict:
    """Synchronously invoke a Lambda and decode its JSON result (asserting no function error)."""
    response = awslambda.invoke(
        FunctionName=function_name,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode(),
    )
    body = response["Payload"].read().decode()
    assert not response.get("FunctionError"), f"{function_name} failed: {body}"
    return json.loads(body)


def _delete_table_if_present(ddb, table_name: str) -> None:
    """Delete the table, tolerating only not-found: the stack may already have removed it."""
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _delete_log_group_if_present(ctx, log_group: str) -> None:
    """Delete the log group, tolerating only not-found: an uninvoked function has none."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=log_group)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _delete_stack_and_wait(ctx, stack_name: str, *, timeout_s=600.0) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE; only a stack that does not exist counts as gone."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if "does not exist" not in exc.response["Error"].get("Message", ""):
                raise
            return "GONE"

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=timeout_s,
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
    timeout_s=600.0,
) -> dict[str, Any]:
    """Deploy a CloudFormation stack (template body str or Path); wait for CREATE_COMPLETE;
    register delete-stack-and-wait teardown. Returns {stack_name,stack_id,outputs:{k:v}}.
    """
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
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name, timeout_s=timeout_s))
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
