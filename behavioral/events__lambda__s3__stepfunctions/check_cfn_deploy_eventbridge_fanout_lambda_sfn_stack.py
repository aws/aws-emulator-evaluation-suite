"""cfn-deploy-eventbridge-fanout-lambda-sfn-stack."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-eventbridge-fanout-lambda-sfn-stack"
GROUP = "deployment-order"
SERVICES = ["events", "lambda", "s3", "stepfunctions"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed EventBridge rule fanning out to Lambda + a state machine invokes both."""
    marker = ctx.unique_name("fanout-marker-")
    definition = {
        "StartAt": "Echo",
        "States": {"Echo": {"Type": "Pass", "End": True}},
    }
    lambda_code = (
        "import boto3, os\n"
        "s3 = boto3.client('s3')\n"
        "def handler(event, context):\n"
        "    detail = event.get('detail', {})\n"
        "    marker = detail.get('marker', 'none')\n"
        "    s3.put_object(Bucket=os.environ['BUCKET_NAME'],\n"
        "                  Key=f'lambda-marker-{marker}.txt',\n"
        "                  Body=marker.encode())\n"
        "    return {'ok': True}\n"
    )
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "MarkerBucket": {"Type": "AWS::S3::Bucket"},
            "LambdaRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                    "Policies": [{
                        "PolicyName": "put-marker",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": ["s3:PutObject"],
                                    "Resource": {"Fn::Sub": "${MarkerBucket.Arn}/*"},
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "logs:CreateLogGroup",
                                        "logs:CreateLogStream",
                                        "logs:PutLogEvents",
                                    ],
                                    "Resource": "*",
                                },
                            ],
                        },
                    }],
                },
            },
            "FanoutFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["LambdaRole", "Arn"]},
                    "Timeout": 30,
                    "Code": {"ZipFile": lambda_code},
                    "Environment": {"Variables": {"BUCKET_NAME": {"Ref": "MarkerBucket"}}},
                },
            },
            "EventRule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "EventPattern": {
                        "source": ["custom.fanout"],
                        "detail-type": ["FanoutTest"],
                    },
                    "Targets": [
                        {"Id": "LambdaTarget", "Arn": {"Fn::GetAtt": ["FanoutFunction", "Arn"]}},
                        {
                            "Id": "SfnTarget",
                            "Arn": {"Ref": "FanoutStateMachine"},
                            "RoleArn": {"Fn::GetAtt": ["EventsRole", "Arn"]},
                        },
                    ],
                },
            },
            "LambdaInvokePermission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "Action": "lambda:InvokeFunction",
                    "FunctionName": {"Ref": "FanoutFunction"},
                    "Principal": "events.amazonaws.com",
                    "SourceArn": {"Fn::GetAtt": ["EventRule", "Arn"]},
                },
            },
            "SfnRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "states.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    }
                },
            },
            "FanoutStateMachine": {
                "Type": "AWS::StepFunctions::StateMachine",
                "Properties": {
                    "RoleArn": {"Fn::GetAtt": ["SfnRole", "Arn"]},
                    "DefinitionString": json.dumps(definition),
                },
            },
            "EventsRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                    "Policies": [{
                        "PolicyName": "start-execution",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": "states:StartExecution",
                                "Resource": {"Ref": "FanoutStateMachine"},
                            }],
                        },
                    }],
                },
            },
        },
        "Outputs": {
            "BucketName": {"Value": {"Ref": "MarkerBucket"}},
            "FunctionName": {"Value": {"Ref": "FanoutFunction"}},
            "StateMachineArn": {"Value": {"Ref": "FanoutStateMachine"}},
        },
    }

    result = _deploy_cfn(ctx, json.dumps(template))
    bucket = result["outputs"]["BucketName"]
    sm_arn = result["outputs"]["StateMachineArn"]
    # The Lambda target writes an object into this CFN-owned bucket, and CloudFormation
    # refuses to delete a non-empty AWS::S3::Bucket — registered after _deploy_cfn so LIFO
    # cleanup empties the bucket before the stack delete is attempted.
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket))

    events = ctx.client("events")
    s3 = ctx.client("s3")
    sfn = ctx.client("stepfunctions")

    put_resp = events.put_events(Entries=[{
        "Source": "custom.fanout",
        "DetailType": "FanoutTest",
        "Detail": json.dumps({"marker": marker}),
    }])
    assert put_resp["FailedEntryCount"] == 0, (
        f"expected put_events to accept the entry, got FailedEntryCount="
        f"{put_resp['FailedEntryCount']}: {put_resp['Entries']}"
    )

    key = f"lambda-marker-{marker}.txt"

    def _lambda_marker_present():
        try:
            return s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode()
        except ClientError:
            return None

    body = _poll_until(
        _lambda_marker_present,
        lambda b: b == marker,
        timeout_s=90,
        interval_s=3.0,
        description="lambda fanout target wrote marker object",
    )
    assert body == marker, f"expected marker object body {marker!r}, got {body!r}"

    def _find_matching_execution():
        execs = sfn.list_executions(stateMachineArn=sm_arn, maxResults=20).get("executions", [])
        for e in execs:
            desc = sfn.describe_execution(executionArn=e["executionArn"])
            try:
                inp = json.loads(desc["input"])
            except (json.JSONDecodeError, KeyError):
                continue
            if inp.get("detail", {}).get("marker") == marker:
                return desc
        return None

    desc = _poll_until(
        _find_matching_execution,
        lambda d: d is not None,
        timeout_s=90,
        interval_s=3.0,
        description="sfn fanout target started an execution for the test event",
    )
    exec_arn = desc["executionArn"]

    final = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=60,
        interval_s=2.0,
        description="sfn fanout execution reached a terminal state",
    )
    assert final["status"] == "SUCCEEDED", f"expected execution to SUCCEED, got {final['status']}"
    out = json.loads(final["output"])
    detail = out.get("detail")
    assert detail is not None, f"expected execution output to include 'detail', got keys {list(out)!r}"
    assert detail["marker"] == marker, f"expected execution output detail.marker {marker!r}, got {detail!r}"


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


def _empty_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
