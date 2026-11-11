"""deploy-cloudwatch-composite-alarm-missing-metric-negative."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudwatch-composite-alarm-missing-metric-negative"
GROUP = "permission-boundary"
SERVICES = ["cloudwatch", "dynamodb", "lambda"]


@tags("axis:negative-delivery", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda lacking cloudwatch:PutMetricData is refused the custom metric it emits, the metric
    never lands and its alarm stays INSUFFICIENT_DATA, read after a control metric published later
    in the same namespace with real permission has landed."""
    function_name = _xname(ctx, "fn")
    alarm_name = _xname(ctx, "alarm")
    namespace = ctx.unique_name("sim2real-xsvc-ns-")
    starved_metric = "ProcessedCount"
    control_metric = "ProcessedCountControl"

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
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
                    # Deliberately missing cloudwatch:PutMetricData — this is the boundary
                    # under test. Only logs permissions are granted.
                    "Policies": [
                        {
                            "PolicyName": "logs-only",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "logs:CreateLogGroup",
                                            "logs:CreateLogStream",
                                            "logs:PutLogEvents",
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
                    "Environment": {"Variables": {"NAMESPACE": namespace, "METRIC": starved_metric}},
                    "Code": {
                        "ZipFile": (
                            "import os\n"
                            "import boto3\n"
                            "from botocore.exceptions import ClientError\n"
                            "def handler(event, context):\n"
                            "    cw = boto3.client('cloudwatch')\n"
                            "    try:\n"
                            "        cw.put_metric_data(\n"
                            "            Namespace=os.environ['NAMESPACE'],\n"
                            "            MetricData=[{'MetricName': os.environ['METRIC'], 'Value': 1}],\n"
                            "        )\n"
                            "    except ClientError as exc:\n"
                            "        return {'refused': exc.response['Error']['Code']}\n"
                            "    return {'refused': None}\n"
                        )
                    },
                },
            },
            "StarvedAlarm": {
                "Type": "AWS::CloudWatch::Alarm",
                "Properties": {
                    "AlarmName": alarm_name,
                    "Namespace": namespace,
                    "MetricName": starved_metric,
                    "Statistic": "Sum",
                    "Period": 60,
                    "EvaluationPeriods": 1,
                    "Threshold": 1,
                    "ComparisonOperator": "GreaterThanOrEqualToThreshold",
                    "TreatMissingData": "missing",
                },
            },
        },
    }

    _deploy_cfn(ctx, json.dumps(template))

    lam = ctx.client("lambda")
    cw = ctx.client("cloudwatch")

    # Each invocation must run and report PutMetricData refused; a function that never ran would
    # leave the metric absent for a reason other than the missing permission.
    start = datetime.now(timezone.utc)
    for i in range(3):
        resp = lam.invoke(FunctionName=function_name, InvocationType="RequestResponse", Payload=b"{}")
        body = resp["Payload"].read()
        assert resp["StatusCode"] == 200 and "FunctionError" not in resp, (
            f"invoke {i + 1} failed: status={resp['StatusCode']!r} "
            f"FunctionError={resp.get('FunctionError')!r} payload={body[:400]!r}"
        )
        refused = json.loads(body).get("refused")
        assert refused == "AccessDenied", (
            f"invoke {i + 1}: PutMetricData without cloudwatch:PutMetricData was not refused "
            f"AccessDenied (handler returned {body[:400]!r})"
        )
        time.sleep(2)

    # POSITIVE CONTROL, ordered after the invocations: the same-namespace control metric,
    # published directly with full permission, lands -- so the CloudWatch pipeline is live.
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
    assert len(control_points) > 0

    # Effect ABSENT: the starved metric has no datapoint and the alarm never left INSUFFICIENT_DATA.
    starved_points = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=starved_metric,
        StartTime=start - timedelta(minutes=1),
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=1),
        Period=60,
        Statistics=["Sum"],
    )["Datapoints"]
    assert starved_points == [], f"expected no datapoints for {starved_metric}, got {starved_points}"
    state = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"]
    assert state == "INSUFFICIENT_DATA", f"alarm unexpectedly moved to {state}"


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
