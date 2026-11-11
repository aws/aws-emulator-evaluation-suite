"""cfn-deploy-scheduler-role-trust-policy-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-scheduler-role-trust-policy-positive"
GROUP = "deployment-order"
SERVICES = ["lambda", "scheduler"]


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """The IAM role deployed by CFN for the schedule's execution role has an
    AssumeRolePolicyDocument that trusts scheduler.amazonaws.com, and that role is what actually
    lets EventBridge Scheduler invoke the Lambda target."""
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    queue_url = sqs.create_queue(QueueName=_xname(ctx, "q"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    scheduler_role_name = _xname(ctx, "srole")
    template = _template(
        account_id=account_id,
        code=_lambda_code(),
        queue_url=queue_url,
        queue_arn=queue_arn,
        lambda_role_name=_xname(ctx, "lrole"),
        scheduler_role_name=scheduler_role_name,
        function_name=_xname(ctx, "fn"),
        schedule_name=_xname(ctx, "sched"),
    )
    _deploy_cfn(ctx, json.dumps(template))

    role = iam.get_role(RoleName=scheduler_role_name)["Role"]
    trust_doc = role["AssumeRolePolicyDocument"]
    trusted_services: set[str] = set()
    for stmt in trust_doc["Statement"]:
        service = stmt.get("Principal", {}).get("Service")
        if isinstance(service, str):
            trusted_services.add(service)
        elif isinstance(service, list):
            trusted_services.update(service)
    assert "scheduler.amazonaws.com" in trusted_services, (
        f"deployed execution role does not trust scheduler.amazonaws.com: {trust_doc}"
    )

    messages = _drain_for_message(ctx, queue_url, timeout_s=240.0)
    assert len(messages) >= 1, "the trusted role failed to actually invoke the Lambda target"
    assert messages[0]["invoked"] is True, (
        f"expected the delivered message to carry invoked=True, got {messages[0]!r}"
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


def _template(
    account_id: str,
    code: str,
    queue_url: str,
    queue_arn: str,
    lambda_role_name: str,
    scheduler_role_name: str,
    function_name: str,
    schedule_name: str,
) -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "LambdaExecutionRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": lambda_role_name,
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
                    "Policies": [
                        {
                            "PolicyName": "send-to-sqs",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "sqs:SendMessage",
                                        "Resource": queue_arn,
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
            "SchedulerExecutionRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": scheduler_role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "scheduler.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                                "Condition": {
                                    "StringEquals": {"aws:SourceAccount": account_id}
                                },
                            }
                        ],
                    },
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
            "Schedule": {
                "Type": "AWS::Scheduler::Schedule",
                "Properties": {
                    "Name": schedule_name,
                    "ScheduleExpression": "rate(1 minute)",
                    "FlexibleTimeWindow": {"Mode": "OFF"},
                    "Target": {
                        "Arn": {"Fn::GetAtt": ["LambdaFunction", "Arn"]},
                        "RoleArn": {"Fn::GetAtt": ["SchedulerExecutionRole", "Arn"]},
                        "Input": json.dumps({"queueUrl": queue_url}),
                    },
                },
            },
        },
        "Outputs": {
            "FunctionArn": {"Value": {"Fn::GetAtt": ["LambdaFunction", "Arn"]}},
            "SchedulerRoleName": {"Value": {"Ref": "SchedulerExecutionRole"}},
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
