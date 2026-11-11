"""deploy-dynamodb-table-stream-arn-exported-correctly."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-dynamodb-table-stream-arn-exported-correctly"
GROUP = "deployment-wiring"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The StreamArn CFN exports via Fn::GetAtt on the table must be the SAME ARN that the
    resulting event source mapping actually consumes, and must match the live table's
    describe_table StreamArn too — checked against real DynamoDB/Lambda state, not the template."""
    function_name = _xname(ctx, "fn")
    table_name = _xname(ctx, "tbl")
    role_name = _xname(ctx, "role")
    template = _build_template(function_name=function_name, table_name=table_name, role_name=role_name)
    stack = _deploy_cfn(ctx, template)
    exported_stream_arn = stack["outputs"]["StreamArn"]
    esm_id = stack["outputs"]["EventSourceMappingId"]

    ddb = ctx.client("dynamodb")
    table_desc = ddb.describe_table(TableName=table_name)["Table"]
    live_stream_arn = table_desc["LatestStreamArn"]
    assert exported_stream_arn == live_stream_arn, (
        f"CFN Fn::GetAtt StreamArn output {exported_stream_arn!r} does not match "
        f"describe_table LatestStreamArn {live_stream_arn!r} for table {table_name!r}"
    )

    lam = ctx.client("lambda")
    mapping = _poll_until(
        lambda: lam.get_event_source_mapping(UUID=esm_id),
        lambda m: m["State"] == "Enabled",
        timeout_s=120,
        interval_s=5.0,
        description="event source mapping reaches Enabled",
    )
    assert mapping["EventSourceArn"] == exported_stream_arn == live_stream_arn, (
        f"event source mapping {esm_id!r} EventSourceArn {mapping['EventSourceArn']!r} diverges from "
        f"CFN-exported StreamArn {exported_stream_arn!r} / live LatestStreamArn {live_stream_arn!r}"
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


_HANDLER_CODE = """def handler(event, context):
    return {"processed": len(event.get("Records", []))}
"""


def _build_template(*, function_name: str, table_name: str, role_name: str) -> str:
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Table": {
                "Type": "AWS::DynamoDB::Table",
                "Properties": {
                    "TableName": table_name,
                    "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                    "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                    "BillingMode": "PAY_PER_REQUEST",
                    "StreamSpecification": {"StreamViewType": "NEW_IMAGE"},
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
                            "PolicyName": "stream-access",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "dynamodb:GetRecords",
                                            "dynamodb:GetShardIterator",
                                            "dynamodb:DescribeStream",
                                            "dynamodb:ListStreams",
                                        ],
                                        "Resource": {"Fn::Sub": "${Table.Arn}/stream/*"},
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
                    "Timeout": 10,
                    "Code": {"ZipFile": _HANDLER_CODE},
                },
            },
            "Esm": {
                "Type": "AWS::Lambda::EventSourceMapping",
                "Properties": {
                    "EventSourceArn": {"Fn::GetAtt": ["Table", "StreamArn"]},
                    "FunctionName": {"Ref": "Function"},
                    "StartingPosition": "LATEST",
                    "BatchSize": 1,
                },
            },
        },
        "Outputs": {
            "StreamArn": {"Value": {"Fn::GetAtt": ["Table", "StreamArn"]}},
            "EventSourceMappingId": {"Value": {"Ref": "Esm"}},
        },
    }
    return json.dumps(template)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
