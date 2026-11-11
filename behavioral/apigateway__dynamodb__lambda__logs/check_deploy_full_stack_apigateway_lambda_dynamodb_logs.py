"""deploy-full-stack-apigateway-lambda-dynamodb-logs."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-full-stack-apigateway-lambda-dynamodb-logs"
GROUP = "deployment-wiring"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:metrics", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Deploys API Gateway + Lambda + DynamoDB + Logs via CFN; a real HTTP request through the
    deployed API must invoke Lambda, which writes an item to DynamoDB and emits a log line to
    the Lambda's CloudWatch log group. All three side effects are observed, not just CREATE_COMPLETE."""
    function_name = _xname(ctx, "fn")
    table_name = _xname(ctx, "tbl")
    role_name = _xname(ctx, "role")
    api_name = _xname(ctx, "api")

    template = _build_template(
        function_name=function_name,
        table_name=table_name,
        role_name=role_name,
        api_name=api_name,
        include_permission=True,
        integration_function_ref="Function",
    )
    stack = _deploy_cfn(ctx, template)
    api_url = f"{ctx.api_url(stack['outputs']['ApiId'], 'test')}/items"

    item_id = ctx.unique_name("item-")
    payload = {"id": item_id, "value": "hello-world"}

    status, body = _poll_until(
        lambda: _http_post(api_url, payload),
        lambda r: r[0] == 200,
        timeout_s=90,
        interval_s=3.0,
        description="API invoke returns 200",
    )
    assert status == 200, f"expected 200, got {status}: {body}"
    assert body.get("ok") is True, f"expected ok=True in response body, got {body}"
    assert body.get("id") == item_id, f"expected response id {item_id!r}, got {body.get('id')!r}"

    ddb = ctx.client("dynamodb")
    item = ddb.get_item(TableName=table_name, Key={"pk": {"S": item_id}}, ConsistentRead=True).get("Item")
    assert item is not None, "item was not written to DynamoDB by the Lambda handler"
    assert item["value"]["S"] == "hello-world", f"expected DynamoDB item value 'hello-world', got {item['value']['S']!r}"

    logs = ctx.client("logs")
    log_group_name = f"/aws/lambda/{function_name}"

    def _find_log() -> list[dict[str, Any]]:
        try:
            resp = logs.filter_log_events(logGroupName=log_group_name)
        except ClientError:
            return []
        return resp.get("events", [])

    events = _poll_until(
        _find_log,
        lambda evs: any(item_id in e.get("message", "") for e in evs),
        timeout_s=90,
        interval_s=5.0,
        description="CloudWatch log line for the invocation",
    )
    assert any(item_id in e["message"] for e in events), (
        f"expected a log event containing {item_id!r} in {log_group_name}, "
        f"got messages={[e.get('message') for e in events]}"
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
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError") or (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" not in exc.response["Error"]["Message"]
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


_HANDLER_CODE = """import json
import os
import boto3

def handler(event, context):
    # Log the body explicitly (not the whole event) so the marker id is never truncated out —
    # the full API-Gateway-proxy event has a large requestContext that can push "body" past a
    # naive character-count truncation of the dumped event.
    print("EVENT_RECEIVED body=" + str(event.get("body")))
    table = boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"])
    body_raw = event.get("body") or "{}"
    try:
        payload = json.loads(body_raw)
    except (TypeError, ValueError):
        payload = {}
    item_id = payload.get("id", "default-id")
    table.put_item(Item={"pk": item_id, "value": payload.get("value", "none")})
    return {"statusCode": 200, "body": json.dumps({"ok": True, "id": item_id})}
"""


def _build_template(
    *,
    function_name: str,
    table_name: str,
    role_name: str,
    api_name: str,
    include_permission: bool,
    integration_function_ref: str,
) -> str:
    resources: dict[str, Any] = {
        "Table": {
            "Type": "AWS::DynamoDB::Table",
            "Properties": {
                "TableName": table_name,
                "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                "BillingMode": "PAY_PER_REQUEST",
            },
        },
        "ExecRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": role_name,
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
                    ],
                },
                "ManagedPolicyArns": ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
                "Policies": [
                    {
                        "PolicyName": "ddb-access",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": ["dynamodb:PutItem", "dynamodb:GetItem"],
                                    "Resource": {"Fn::GetAtt": ["Table", "Arn"]},
                                }
                            ],
                        },
                    }
                ],
            },
        },
        "Function": {
            "Type": "AWS::Lambda::Function",
            "DependsOn": "ExecRole",
            "Properties": {
                "FunctionName": function_name,
                "Runtime": "python3.12",
                "Handler": "index.handler",
                "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                "Timeout": 15,
                "Environment": {"Variables": {"TABLE_NAME": table_name}},
                "Code": {"ZipFile": _HANDLER_CODE},
            },
        },
        "RestApi": {"Type": "AWS::ApiGateway::RestApi", "Properties": {"Name": api_name}},
        "ItemsResource": {
            "Type": "AWS::ApiGateway::Resource",
            "Properties": {
                "RestApiId": {"Ref": "RestApi"},
                "ParentId": {"Fn::GetAtt": ["RestApi", "RootResourceId"]},
                "PathPart": "items",
            },
        },
        "Method": {
            "Type": "AWS::ApiGateway::Method",
            "Properties": {
                "RestApiId": {"Ref": "RestApi"},
                "ResourceId": {"Ref": "ItemsResource"},
                "HttpMethod": "POST",
                "AuthorizationType": "NONE",
                "Integration": {
                    "Type": "AWS_PROXY",
                    "IntegrationHttpMethod": "POST",
                    "Uri": {
                        "Fn::Sub": (
                            "arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/"
                            f"${{{integration_function_ref}.Arn}}/invocations"
                        )
                    },
                },
            },
        },
        "Deployment": {
            "Type": "AWS::ApiGateway::Deployment",
            "DependsOn": "Method",
            "Properties": {"RestApiId": {"Ref": "RestApi"}},
        },
        "Stage": {
            "Type": "AWS::ApiGateway::Stage",
            "Properties": {"RestApiId": {"Ref": "RestApi"}, "DeploymentId": {"Ref": "Deployment"}, "StageName": "test"},
        },
    }
    if include_permission:
        resources["InvokePermission"] = {
            "Type": "AWS::Lambda::Permission",
            "Properties": {
                "Action": "lambda:InvokeFunction",
                "FunctionName": {"Ref": "Function"},
                "Principal": "apigateway.amazonaws.com",
                "SourceArn": {"Fn::Sub": "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${RestApi}/*/*/items"},
            },
        }
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": {
            "ApiId": {"Value": {"Ref": "RestApi"}},
            "TableName": {"Value": {"Ref": "Table"}},
            "FunctionName": {"Value": {"Ref": "Function"}},
            "FunctionArn": {"Value": {"Fn::GetAtt": ["Function", "Arn"]}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["ExecRole", "Arn"]}},
        },
    }
    return json.dumps(template)


def _http_post(url: str, payload: dict[str, Any], timeout: float = 10.0):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"), method="POST", headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = raw
        return e.code, parsed
    except urllib.error.URLError as e:
        return -1, str(e)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
