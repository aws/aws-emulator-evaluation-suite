"""deploy-lambda-execution-role-missing-cloudwatch-permission-negative."""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-lambda-execution-role-missing-cloudwatch-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["cloudwatch", "dynamodb", "lambda"]


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html
@tags("axis:negative-delivery", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A stream-triggered Lambda whose role omits cloudwatch:PutMetricData still processes the
    record, but its custom metric never lands until that permission is granted to the same role
    and a fresh record flows through."""
    source_table = _xname(ctx, "src")
    results_table = _xname(ctx, "dst")
    function_name = _xname(ctx, "fn")
    namespace = ctx.unique_name("sim2real-xsvc-ns-")
    starved_metric = "ItemsProcessed"
    control_metric = "ItemsProcessedControl"

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
                    # Full stream-read + results-write permission, but NO
                    # cloudwatch:PutMetricData — this is the boundary under test.
                    "Policies": [
                        {
                            "PolicyName": "stream-and-write-no-cloudwatch",
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
                    "Environment": {
                        "Variables": {
                            "RESULTS_TABLE": results_table,
                            "NAMESPACE": namespace,
                            "METRIC": starved_metric,
                        }
                    },
                    "Code": {
                        "ZipFile": (
                            "import os\n"
                            "import boto3\n"
                            "def handler(event, context):\n"
                            "    ddb = boto3.client('dynamodb')\n"
                            "    cw = boto3.client('cloudwatch')\n"
                            "    for record in event.get('Records', []):\n"
                            "        if record.get('eventName') != 'INSERT':\n"
                            "            continue\n"
                            "        pk = record['dynamodb']['NewImage']['pk']['S']\n"
                            "        ddb.put_item(\n"
                            "            TableName=os.environ['RESULTS_TABLE'],\n"
                            "            Item={'pk': {'S': pk}, 'processed': {'BOOL': True}},\n"
                            "        )\n"
                            "        try:\n"
                            "            cw.put_metric_data(\n"
                            "                Namespace=os.environ['NAMESPACE'],\n"
                            "                MetricData=[{'MetricName': os.environ['METRIC'], 'Value': 1}],\n"
                            "            )\n"
                            "        except Exception:\n"
                            "            pass\n"
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
    cw = ctx.client("cloudwatch")

    mapping_uuid = lam.list_event_source_mappings(FunctionName=function_name)["EventSourceMappings"][0]["UUID"]
    _wait_esm_enabled(ctx, mapping_uuid)

    start = datetime.now(timezone.utc)
    item_pk = f"trigger-{uuid.uuid4()}"
    ddb.put_item(TableName=source_table, Item={"pk": {"S": item_pk}})

    # POSITIVE effect: DynamoDB stream processing succeeds end-to-end despite the missing
    # CloudWatch permission — the marker item is written by the Lambda function.
    def _get_result():
        try:
            return ddb.get_item(TableName=results_table, Key={"pk": {"S": item_pk}}).get("Item")
        except ClientError:
            return None

    item = _poll_until(
        _get_result,
        lambda i: i is not None,
        timeout_s=90.0,
        interval_s=2.0,
        description=f"Lambda-written marker item for {item_pk}",
    )
    assert item is not None, f"expected a results-table item for {item_pk}, got none"
    assert item["processed"]["BOOL"] is True, f"expected processed=True, got {item!r}"

    # POSITIVE CONTROL, ordered after the Lambda's attempt: same namespace, published directly
    # with full permission, lands -- the barrier the absence below is read behind.
    cw.put_metric_data(Namespace=namespace, MetricData=[{"MetricName": control_metric, "Value": 1}])
    control_points = _poll_until(
        lambda: cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=control_metric,
            StartTime=datetime.now(timezone.utc) - timedelta(minutes=5),
            EndTime=datetime.now(timezone.utc) + timedelta(minutes=1),
            Period=60,
            Statistics=["Sum"],
        )["Datapoints"],
        lambda dps: len(dps) > 0,
        timeout_s=180.0,
        interval_s=2.0,
        description=f"control metric {control_metric} landing",
    )
    assert len(control_points) > 0, f"expected {control_metric} to land via direct caller, got none"

    # Effect ABSENT: the metric the Lambda tried (and failed) to emit has no datapoint.
    starved_points = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=starved_metric,
        StartTime=start - timedelta(minutes=1),
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=1),
        Period=60,
        Statistics=["Sum"],
    )["Datapoints"]
    assert starved_points == [], f"expected no datapoints for {starved_metric}, got {starved_points}"

    # RESTORE: grant the SAME role the missing permission, drive a fresh record through the SAME
    # stream/function/role, and demand the SAME starved metric now lands — isolating the cause to
    # exactly the missing permission rather than to namespace/region/wiring health.
    iam = ctx.client("iam")
    role_arn = lam.get_function_configuration(FunctionName=function_name)["Role"]
    role_name = role_arn.rsplit("/", 1)[-1]
    restore_policy_name = "sim2real-restore-cloudwatch-putmetricdata"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=restore_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "cloudwatch:PutMetricData", "Resource": "*"}],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=restore_policy_name))

    # IAM policy attachment is eventually consistent for the role's next assume/use, and CloudWatch
    # ingestion has its own lag — so retry the real effect (a fresh trigger through the SAME
    # role/function/stream) against a deadline, rather than guessing a fixed propagation delay.
    def _restored_metric_probe():
        restored_pk = f"trigger-{uuid.uuid4()}"
        ddb.put_item(TableName=source_table, Item={"pk": {"S": restored_pk}})
        return cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=starved_metric,
            StartTime=start - timedelta(minutes=1),
            EndTime=datetime.now(timezone.utc) + timedelta(minutes=1),
            Period=60,
            Statistics=["Sum"],
        )["Datapoints"]

    # IAM propagation to the running function plus metric ingestion: up to 270 s.
    left = ctx.time_left()
    restore_timeout_s = 270.0 if left is None else max(1.0, min(270.0, left - 5.0))
    restored_points = _poll_until(
        _restored_metric_probe,
        lambda dps: len(dps) > 0,
        timeout_s=restore_timeout_s,
        interval_s=2.0,
        description=f"starved metric {starved_metric} landing after permission restore (retrying trigger for IAM propagation)",
    )
    assert len(restored_points) > 0, (
        f"expected {starved_metric} to land via the same role after restoring cloudwatch:PutMetricData, got none"
    )


# ===== helpers =====
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
