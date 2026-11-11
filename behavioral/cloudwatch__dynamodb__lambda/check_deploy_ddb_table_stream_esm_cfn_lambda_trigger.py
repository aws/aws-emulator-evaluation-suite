"""deploy-ddb-table-stream-esm-cfn-lambda-trigger."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ddb-table-stream-esm-cfn-lambda-trigger"
GROUP = "deployment-order"
SERVICES = ["cloudwatch", "dynamodb", "lambda"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed DynamoDB table with a StreamSpecification plus an EventSourceMapping
    resource actually triggers the Lambda function on item writes — the function's processing
    of the real stream record must be observable, not just the mapping's existence."""
    source_table = _xname(ctx, "src")
    results_table = _xname(ctx, "dst")
    function_name = _xname(ctx, "fn")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "SourceTable": {
                "Type": "AWS::DynamoDB::Table",
                "Properties": {
                    "TableName": source_table,
                    "BillingMode": "PAY_PER_REQUEST",
                    "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                    "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                    "StreamSpecification": {"StreamViewType": "NEW_IMAGE"},
                },
            },
            "ResultsTable": {
                "Type": "AWS::DynamoDB::Table",
                "Properties": {
                    "TableName": results_table,
                    "BillingMode": "PAY_PER_REQUEST",
                    "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                    "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                },
            },
            "LambdaRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "lambda.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "stream-and-write",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "logs:CreateLogGroup",
                                            "logs:CreateLogStream",
                                            "logs:PutLogEvents",
                                            "dynamodb:GetRecords",
                                            "dynamodb:GetShardIterator",
                                            "dynamodb:DescribeStream",
                                            "dynamodb:ListStreams",
                                        ],
                                        "Resource": "*",
                                    },
                                    {
                                        "Effect": "Allow",
                                        "Action": "dynamodb:PutItem",
                                        "Resource": {"Fn::GetAtt": ["ResultsTable", "Arn"]},
                                    },
                                ],
                            },
                        }
                    ],
                },
            },
            "Function": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": function_name,
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["LambdaRole", "Arn"]},
                    "Timeout": 15,
                    "Environment": {"Variables": {"RESULTS_TABLE": results_table}},
                    "Code": {
                        "ZipFile": (
                            "import os\n"
                            "import boto3\n"
                            "def handler(event, context):\n"
                            "    ddb = boto3.client('dynamodb')\n"
                            "    for record in event.get('Records', []):\n"
                            "        if record.get('eventName') != 'INSERT':\n"
                            "            continue\n"
                            "        pk = record['dynamodb']['NewImage']['pk']['S']\n"
                            "        ddb.put_item(\n"
                            "            TableName=os.environ['RESULTS_TABLE'],\n"
                            "            Item={'pk': {'S': pk}, 'processed': {'BOOL': True}},\n"
                            "        )\n"
                            "    return {'ok': True}\n"
                        )
                    },
                },
            },
            "Mapping": {
                "Type": "AWS::Lambda::EventSourceMapping",
                "Properties": {
                    "EventSourceArn": {"Fn::GetAtt": ["SourceTable", "StreamArn"]},
                    "FunctionName": {"Ref": "Function"},
                    "StartingPosition": "TRIM_HORIZON",
                    "BatchSize": 5,
                },
            },
        },
    }

    _deploy_cfn(ctx, json.dumps(template))

    lam = ctx.client("lambda")
    ddb = ctx.client("dynamodb")

    mapping_uuid = lam.list_event_source_mappings(FunctionName=function_name)["EventSourceMappings"][0]["UUID"]
    _wait_esm_enabled(ctx, mapping_uuid)

    item_pk = f"trigger-{uuid.uuid4()}"
    ddb.put_item(TableName=source_table, Item={"pk": {"S": item_pk}})

    def _get_result():
        try:
            return ddb.get_item(TableName=results_table, Key={"pk": {"S": item_pk}}).get("Item")
        except ClientError:
            return None

    item = _poll_until(
        _get_result,
        lambda i: i is not None,
        timeout_s=90.0,
        interval_s=3.0,
        description=f"Lambda-written marker item for {item_pk}",
    )
    assert item is not None, f"no item written to {results_table} for pk={item_pk} by the stream-triggered Lambda"
    assert item["processed"]["BOOL"] is True, f"expected processed=True on {results_table}/{item_pk}, got {item!r}"


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


def _wait_esm_enabled(ctx, mapping_uuid: str, timeout_s: float = 120.0) -> None:
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=mapping_uuid)["State"],
        lambda s: s == "Enabled",
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"event source mapping {mapping_uuid} becoming Enabled",
    )


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


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template,
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
