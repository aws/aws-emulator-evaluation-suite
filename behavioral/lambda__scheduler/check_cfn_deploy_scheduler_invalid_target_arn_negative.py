"""cfn-deploy-scheduler-invalid-target-arn-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-scheduler-invalid-target-arn-negative"
GROUP = "permission-boundary"
SERVICES = ["lambda", "scheduler"]


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A schedule targeting a nonexistent Lambda ARN deploys (Scheduler does not validate target
    existence) but delivers no invocation, while a sibling schedule targeting the real function
    does."""
    sqs = ctx.client("sqs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region

    control_queue_url = sqs.create_queue(
        QueueName=_xname(ctx, "ctlq"), tags=_xsvc_resource_tags()
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=control_queue_url))
    control_queue_arn = sqs.get_queue_attributes(
        QueueUrl=control_queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    broken_queue_url = sqs.create_queue(
        QueueName=_xname(ctx, "brkq"), tags=_xsvc_resource_tags()
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=broken_queue_url))

    bogus_function_name = _xname(ctx, "ghost-fn")
    bogus_arn = f"arn:aws:lambda:{region}:{account_id}:function:{bogus_function_name}"

    template = _template_bad_arn(
        account_id=account_id,
        code=_lambda_code(),
        control_queue_url=control_queue_url,
        broken_queue_url=broken_queue_url,
        control_queue_arn=control_queue_arn,
        lambda_role_name=_xname(ctx, "lrole"),
        good_role_name=_xname(ctx, "grole"),
        broken_role_name=_xname(ctx, "brole"),
        function_name=_xname(ctx, "fn"),
        good_schedule_name=_xname(ctx, "gsched"),
        broken_schedule_name=_xname(ctx, "bsched"),
        bogus_arn=bogus_arn,
    )
    result = _deploy_cfn(ctx, json.dumps(template))
    assert result["stack_id"], "stack creation should succeed despite the dangling target ARN"

    # Positive control in the SAME file: the sibling schedule targeting a real function works.
    good_messages = _drain_for_message(ctx, control_queue_url, timeout_s=240.0)
    assert len(good_messages) >= 1, "control schedule (real target) never fired"
    assert good_messages[0]["invoked"] is True

    # The schedule targeting the nonexistent function must never deliver an invocation.
    broken_messages = _collect_messages(ctx, broken_queue_url, window_s=180.0)
    assert broken_messages == [], (
        f"schedule targeting a nonexistent Lambda function must never invoke it, got {broken_messages}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
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


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; errors swallowed by on_cleanup)."""
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
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
    """Deploy a CloudFormation stack (template body str or Path); wait for CREATE_COMPLETE;
    register delete-stack-and-wait teardown. Returns {stack_name,stack_id,outputs:{k:v}}."""
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


def _lambda_code() -> str:
    return (
        "import json\n"
        "import boto3\n"
        "\n"
        "def handler(event, context):\n"
        "    sqs = boto3.client('sqs')\n"
        "    payload = event if isinstance(event, dict) else json.loads(event)\n"
        "    queue_url = payload['queueUrl']\n"
        "    sqs.send_message(\n"
        "        QueueUrl=queue_url,\n"
        "        MessageBody=json.dumps({'invoked': True, 'requestId': context.aws_request_id}),\n"
        "    )\n"
        "    return {'ok': True}\n"
    )


def _template_bad_arn(
    account_id: str,
    code: str,
    control_queue_url: str,
    broken_queue_url: str,
    control_queue_arn: str,
    lambda_role_name: str,
    good_role_name: str,
    broken_role_name: str,
    function_name: str,
    good_schedule_name: str,
    broken_schedule_name: str,
    bogus_arn: str,
) -> dict[str, Any]:
    lambda_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    scheduler_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "scheduler.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            }
        ],
    }
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "LambdaExecutionRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": lambda_role_name,
                    "AssumeRolePolicyDocument": lambda_trust,
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    ],
                    "Policies": [
                        {
                            "PolicyName": "send-to-sqs",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "sqs:SendMessage",
                                        "Resource": control_queue_arn,
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "LambdaFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": function_name,
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["LambdaExecutionRole", "Arn"]},
                    "Timeout": 30,
                    "Code": {"ZipFile": code},
                },
            },
            "GoodSchedulerRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": good_role_name,
                    "AssumeRolePolicyDocument": scheduler_trust,
                    "Policies": [
                        {
                            "PolicyName": "invoke-lambda",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "lambda:InvokeFunction",
                                        "Resource": {
                                            "Fn::GetAtt": ["LambdaFunction", "Arn"]
                                        },
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "BrokenSchedulerRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": broken_role_name,
                    "AssumeRolePolicyDocument": scheduler_trust,
                    "Policies": [
                        {
                            # Broad permission on purpose: IAM must NOT be what blocks this
                            # invocation -- the target simply does not exist.
                            "PolicyName": "invoke-lambda-broad",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "lambda:InvokeFunction",
                                        "Resource": "*",
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "GoodSchedule": {
                "Type": "AWS::Scheduler::Schedule",
                "Properties": {
                    "Name": good_schedule_name,
                    "ScheduleExpression": "rate(1 minute)",
                    "FlexibleTimeWindow": {"Mode": "OFF"},
                    "Target": {
                        "Arn": {"Fn::GetAtt": ["LambdaFunction", "Arn"]},
                        "RoleArn": {"Fn::GetAtt": ["GoodSchedulerRole", "Arn"]},
                        "Input": json.dumps({"queueUrl": control_queue_url}),
                    },
                },
            },
            "BrokenSchedule": {
                "Type": "AWS::Scheduler::Schedule",
                "Properties": {
                    "Name": broken_schedule_name,
                    "ScheduleExpression": "rate(1 minute)",
                    "FlexibleTimeWindow": {"Mode": "OFF"},
                    "Target": {
                        "Arn": bogus_arn,
                        "RoleArn": {"Fn::GetAtt": ["BrokenSchedulerRole", "Arn"]},
                        "Input": json.dumps({"queueUrl": broken_queue_url}),
                    },
                },
            },
        },
    }


def _drain_for_message(ctx, queue_url, timeout_s=240.0):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    collected: list[dict[str, Any]] = []
    while time.monotonic() < deadline and not collected:
        remaining = max(1, min(int(deadline - time.monotonic()), 20))
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=5, WaitTimeSeconds=remaining
        )
        for m in resp.get("Messages", []):
            collected.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return collected


def _collect_messages(ctx, queue_url, window_s=180.0):
    """Poll for the FULL window (never stopping early) and return every message observed."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + window_s
    collected: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        remaining = max(1, min(int(deadline - time.monotonic()), 20))
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=remaining
        )
        for m in resp.get("Messages", []):
            collected.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return collected


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
