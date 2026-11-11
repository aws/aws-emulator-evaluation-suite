"""cfn-deploy-logs-subscription-filter-lambda-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-logs-subscription-filter-lambda-positive"
GROUP = "deployment-order"
SERVICES = ["cloudwatch", "lambda", "logs"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack's subscription filter delivers a log event written to the source log group to the
    destination function, which logs the event's marker."""
    src_log_group = _xname(ctx, "srclg")
    dst_fn_name = _xname(ctx, "dstfn")
    marker = ctx.unique_name("sim2real-marker-")

    dest_code = (
        "import base64, gzip, json\n"
        "def handler(event, context):\n"
        "    payload = base64.b64decode(event['awslogs']['data'])\n"
        "    data = json.loads(gzip.decompress(payload))\n"
        "    for e in data.get('logEvents', []):\n"
        "        print('RECEIVED:', e.get('message'))\n"
        "    return {'count': len(data.get('logEvents', []))}\n"
    )

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "SrcLogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {"LogGroupName": src_log_group, "RetentionInDays": 1},
            },
            "DstExecRole": {
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
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    ],
                },
            },
            "DstFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": dst_fn_name,
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["DstExecRole", "Arn"]},
                    "Code": {"ZipFile": dest_code},
                    "Timeout": 30,
                },
            },
            "DstPermission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "Action": "lambda:InvokeFunction",
                    "FunctionName": {"Ref": "DstFunction"},
                    "Principal": "logs.amazonaws.com",
                    "SourceArn": {"Fn::GetAtt": ["SrcLogGroup", "Arn"]},
                    "SourceAccount": {"Ref": "AWS::AccountId"},
                },
            },
            "SubFilter": {
                "Type": "AWS::Logs::SubscriptionFilter",
                "DependsOn": ["DstPermission"],
                "Properties": {
                    "LogGroupName": {"Ref": "SrcLogGroup"},
                    "FilterPattern": "",
                    "DestinationArn": {"Fn::GetAtt": ["DstFunction", "Arn"]},
                },
            },
        },
        "Outputs": {
            "SrcLogGroupName": {"Value": {"Ref": "SrcLogGroup"}},
            "DstFunctionName": {"Value": {"Ref": "DstFunction"}},
        },
    }

    _deploy_cfn(ctx, json.dumps(template))

    logs = ctx.client("logs")

    stream_name = ctx.unique_name("sim2real-stream-")
    logs.create_log_stream(logGroupName=src_log_group, logStreamName=stream_name)

    start_time_ms = int(time.time() * 1000)
    logs.put_log_events(
        logGroupName=src_log_group,
        logStreamName=stream_name,
        logEvents=[{"timestamp": start_time_ms, "message": marker}],
    )

    dst_log_group = f"/aws/lambda/{dst_fn_name}"

    def _find_marker():
        try:
            resp = logs.filter_log_events(
                logGroupName=dst_log_group,
                startTime=start_time_ms - 5000,
                filterPattern="RECEIVED",
            )
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return []
            raise
        return resp.get("events", [])

    events = _poll_until(
        _find_marker,
        lambda evs: any(marker in e["message"] for e in evs),
        timeout_s=120,
        interval_s=5.0,
        description="destination Lambda log to contain delivered marker message",
    )
    assert any(marker in e["message"] for e in events), (
        f"expected a destination-lambda log line containing marker {marker!r}, "
        f"got {[e['message'] for e in events]!r}"
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
            err = exc.response["Error"]
            if err["Code"] != "StackNotFoundException" and not (
                err["Code"] == "ValidationError" and "does not exist" in err.get("Message", "")
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
    ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0
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
            in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
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
