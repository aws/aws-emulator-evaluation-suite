"""deploy-ddb-stream-lambda-cloudwatch-dashboard."""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ddb-stream-lambda-cloudwatch-dashboard"
GROUP = "deployment-order"
SERVICES = ["cloudwatch", "dynamodb", "lambda"]


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html
@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "concern:metrics", "concern:representation", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A deployed template wiring a DynamoDB stream event source mapping to Lambda also
    provisions a CloudWatch dashboard whose IteratorAge widget reflects live metric data
    produced by real stream processing."""
    table_name = _xname(ctx, "tbl")
    function_name = _xname(ctx, "fn")
    dashboard_name = _xname(ctx, "dash")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Table": {
                "Type": "AWS::DynamoDB::Table",
                "Properties": {
                    "TableName": table_name,
                    "BillingMode": "PAY_PER_REQUEST",
                    "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                    "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                    "StreamSpecification": {"StreamViewType": "NEW_IMAGE"},
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
                            "PolicyName": "logs-and-stream",
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
                                    }
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
                    "Timeout": 10,
                    "Code": {
                        "ZipFile": (
                            "def handler(event, context):\n"
                            "    return {'processed': len(event.get('Records', []))}\n"
                        )
                    },
                },
            },
            "Mapping": {
                "Type": "AWS::Lambda::EventSourceMapping",
                "Properties": {
                    "EventSourceArn": {"Fn::GetAtt": ["Table", "StreamArn"]},
                    "FunctionName": {"Ref": "Function"},
                    "StartingPosition": "TRIM_HORIZON",
                    "BatchSize": 1,
                },
            },
            "Dashboard": {
                "Type": "AWS::CloudWatch::Dashboard",
                "Properties": {
                    "DashboardName": dashboard_name,
                    "DashboardBody": json.dumps(
                        {
                            "widgets": [
                                {
                                    "type": "metric",
                                    "x": 0,
                                    "y": 0,
                                    "width": 12,
                                    "height": 6,
                                    "properties": {
                                        "metrics": [
                                            [
                                                "AWS/Lambda",
                                                "IteratorAge",
                                                "FunctionName",
                                                function_name,
                                                {"stat": "Maximum"},
                                            ]
                                        ],
                                        "period": 60,
                                        "region": ctx.region,
                                        "title": "IteratorAge",
                                    },
                                }
                            ]
                        }
                    ),
                },
            },
        },
    }

    _deploy_cfn(ctx, json.dumps(template))

    lam = ctx.client("lambda")
    ddb = ctx.client("dynamodb")
    cw = ctx.client("cloudwatch")

    mapping_uuid = lam.list_event_source_mappings(FunctionName=function_name)["EventSourceMappings"][0]["UUID"]
    _wait_esm_enabled(ctx, mapping_uuid)

    # Verify the dashboard body was stored faithfully before relying on it as the source of the
    # metric spec we then query.
    body = json.loads(cw.get_dashboard(DashboardName=dashboard_name)["DashboardBody"])
    metric_spec = body["widgets"][0]["properties"]["metrics"][0]
    namespace, metric_name, dim_name, dim_value = metric_spec[0], metric_spec[1], metric_spec[2], metric_spec[3]
    got_spec = (namespace, metric_name, dim_name, dim_value)
    want_spec = ("AWS/Lambda", "IteratorAge", "FunctionName", function_name)
    assert got_spec == want_spec, f"dashboard widget metric spec {got_spec} != deployed spec {want_spec}"

    start = datetime.now(timezone.utc)
    for i in range(5):
        ddb.put_item(TableName=table_name, Item={"pk": {"S": f"item-{uuid.uuid4()}-{i}"}})

    def _datapoints():
        return cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=[{"Name": dim_name, "Value": dim_value}],
            StartTime=start - timedelta(minutes=1),
            EndTime=datetime.now(timezone.utc) + timedelta(minutes=1),
            Period=60,
            Statistics=["Maximum"],
        )["Datapoints"]

    datapoints = _poll_until(
        _datapoints,
        lambda dps: len(dps) > 0,
        timeout_s=_budget_s(ctx, 300.0), ctx=ctx,
        interval_s=2.0,
        description="IteratorAge metric datapoint from the dashboard widget",
    )
    assert len(datapoints) > 0, "no IteratorAge datapoint appeared for the dashboard's metric spec"
    elapsed_ms = (datetime.now(timezone.utc) - start).total_seconds() * 1000
    maximum = max(dp["Maximum"] for dp in datapoints)
    assert 0 <= maximum <= elapsed_ms, (
        f"IteratorAge Maximum={maximum}ms outside the plausible range [0, {elapsed_ms}ms] "
        "elapsed since the first stream write"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition",
                ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
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
        timeout_s=_budget_s(ctx, timeout_s), ctx=ctx,
        interval_s=2.0,
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
        timeout_s=_budget_s(ctx, timeout_s), ctx=ctx,
        interval_s=2.0,
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
