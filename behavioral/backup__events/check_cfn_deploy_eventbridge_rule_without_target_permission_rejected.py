"""cfn-deploy-eventbridge-rule-without-target-permission-rejected."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-eventbridge-rule-without-target-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["backup", "events"]

_LAMBDA_SRC_GOOD = (
    "import boto3, os, json\n\n"
    "def handler(event, context):\n"
    "    sqs = boto3.client('sqs')\n"
    "    sqs.send_message(QueueUrl=os.environ['QUEUE_URL'], MessageBody=json.dumps(event))\n"
    "    return {'ok': True}\n"
)
_LAMBDA_SRC_BAD = "def handler(event, context):\n    return {'ok': True}\n"

_TEMPLATE = json.dumps(
    {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "LambdaExecRoleName": {"Type": "String"},
            "GoodFunctionName": {"Type": "String"},
            "BadFunctionName": {"Type": "String"},
            "GoodRuleName": {"Type": "String"},
            "BadRuleName": {"Type": "String"},
            "SuccessQueueName": {"Type": "String"},
            "DlqGoodName": {"Type": "String"},
            "DlqBadName": {"Type": "String"},
        },
        "Resources": {
            "SuccessQueue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": {"Ref": "SuccessQueueName"}},
            },
            "DlqGoodQueue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": {"Ref": "DlqGoodName"}},
            },
            "DlqBadQueue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": {"Ref": "DlqBadName"}},
            },
            "DlqGoodQueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "DlqGoodQueue"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "events.amazonaws.com"},
                                "Action": "sqs:SendMessage",
                                "Resource": {"Fn::GetAtt": ["DlqGoodQueue", "Arn"]},
                                "Condition": {
                                    "ArnEquals": {
                                        "aws:SourceArn": {"Fn::GetAtt": ["GoodRule", "Arn"]}
                                    }
                                },
                            }
                        ],
                    },
                },
            },
            "DlqBadQueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "DlqBadQueue"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "events.amazonaws.com"},
                                "Action": "sqs:SendMessage",
                                "Resource": {"Fn::GetAtt": ["DlqBadQueue", "Arn"]},
                                "Condition": {
                                    "ArnEquals": {
                                        "aws:SourceArn": {"Fn::GetAtt": ["BadRule", "Arn"]}
                                    }
                                },
                            }
                        ],
                    },
                },
            },
            "LambdaExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": {"Ref": "LambdaExecRoleName"},
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
                            "PolicyName": "SqsSend",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "sqs:SendMessage",
                                        "Resource": {"Fn::GetAtt": ["SuccessQueue", "Arn"]},
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "GoodFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": {"Ref": "GoodFunctionName"},
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["LambdaExecRole", "Arn"]},
                    "Runtime": "python3.12",
                    "Timeout": 15,
                    "Environment": {"Variables": {"QUEUE_URL": {"Ref": "SuccessQueue"}}},
                    "Code": {"ZipFile": _LAMBDA_SRC_GOOD},
                },
            },
            "BadFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": {"Ref": "BadFunctionName"},
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["LambdaExecRole", "Arn"]},
                    "Runtime": "python3.12",
                    "Timeout": 15,
                    "Code": {"ZipFile": _LAMBDA_SRC_BAD},
                },
            },
            # GoodFunction gets the resource policy that lets EventBridge invoke it.
            "GoodPermission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "Action": "lambda:InvokeFunction",
                    "FunctionName": {"Ref": "GoodFunction"},
                    "Principal": "events.amazonaws.com",
                    "SourceArn": {"Fn::GetAtt": ["GoodRule", "Arn"]},
                },
            },
            # BadFunction deliberately has NO AWS::Lambda::Permission -> EventBridge cannot
            # invoke it and the event should be dead-lettered instead.
            "GoodRule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "Name": {"Ref": "GoodRuleName"},
                    "EventPattern": {
                        "source": ["sim2real.backup"],
                        "detail-type": ["Backup Job State Change"],
                    },
                    "Targets": [
                        {
                            # Default retry policy (no override): a transient cold-start hiccup
                            # gets retried rather than immediately dead-lettered, so DlqGoodQueue
                            # staying empty is a genuine signal, not a timing artifact.
                            "Id": "GoodTarget",
                            "Arn": {"Fn::GetAtt": ["GoodFunction", "Arn"]},
                            "DeadLetterConfig": {"Arn": {"Fn::GetAtt": ["DlqGoodQueue", "Arn"]}},
                        }
                    ],
                },
            },
            "BadRule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "Name": {"Ref": "BadRuleName"},
                    "EventPattern": {
                        "source": ["sim2real.backup"],
                        "detail-type": ["Backup Job State Change"],
                    },
                    "Targets": [
                        {
                            "Id": "BadTarget",
                            "Arn": {"Fn::GetAtt": ["BadFunction", "Arn"]},
                            "RetryPolicy": {"MaximumRetryAttempts": 0},
                            "DeadLetterConfig": {"Arn": {"Fn::GetAtt": ["DlqBadQueue", "Arn"]}},
                        }
                    ],
                },
            },
        },
        "Outputs": {
            "SuccessQueueUrl": {"Value": {"Ref": "SuccessQueue"}},
            "DlqGoodUrl": {"Value": {"Ref": "DlqGoodQueue"}},
            "DlqBadUrl": {"Value": {"Ref": "DlqBadQueue"}},
        },
    }
)


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule whose Lambda target lacks the invoke permission never delivers the event, which lands
    in the target's dead-letter queue, while a sibling rule with the same pattern and a permitted
    Lambda target delivers it."""
    params = {
        "LambdaExecRoleName": _xname(ctx, "lrole"),
        "GoodFunctionName": _xname(ctx, "goodfn"),
        "BadFunctionName": _xname(ctx, "badfn"),
        "GoodRuleName": _xname(ctx, "goodrule"),
        "BadRuleName": _xname(ctx, "badrule"),
        "SuccessQueueName": _xname(ctx, "successq"),
        "DlqGoodName": _xname(ctx, "dlqgood"),
        "DlqBadName": _xname(ctx, "dlqbad"),
    }
    stack = _deploy_cfn(ctx, _TEMPLATE, parameters=params, timeout_s=240)
    outputs = stack["outputs"]
    success_queue = outputs["SuccessQueueUrl"]
    dlq_good = outputs["DlqGoodUrl"]
    dlq_bad = outputs["DlqBadUrl"]

    events = ctx.client("events")
    sqs = ctx.client("sqs")
    lambda_client = ctx.client("lambda")

    for fn_name in (params["GoodFunctionName"], params["BadFunctionName"]):
        _poll_until(
            lambda fn=fn_name: lambda_client.get_function(FunctionName=fn)["Configuration"]["State"],
            lambda s: s == "Active",
            timeout_s=60,
            interval_s=3.0,
            description=f"lambda function {fn_name} become Active",
        )

    # EventBridge drops customer PutEvents entries whose Source is in the reserved "aws."
    # namespace, so a non-reserved source exercises the same pattern-matching and
    # target-invocation-permission mechanics.
    job_id = ctx.unique_name("sim2real-job-")
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.backup",
                "DetailType": "Backup Job State Change",
                "Detail": json.dumps({"backupJobId": job_id, "state": "COMPLETED"}),
            }
        ]
    )

    # Positive control: the correctly-permissioned target IS invoked and does its work.
    success_msgs = _poll_until(
        lambda: _drain(sqs, success_queue),
        lambda msgs: len(msgs) >= 1,
        timeout_s=90,
        interval_s=3.0,
        description="correctly-permissioned Lambda target delivering to its success queue",
    )
    assert any(job_id in m for m in success_msgs), "success queue never saw the triggering event"

    # Negative effect: the un-permissioned target's invocation fails and is dead-lettered.
    bad_dlq_msgs = _poll_until(
        lambda: _drain(sqs, dlq_bad),
        lambda msgs: len(msgs) >= 1,
        timeout_s=90,
        interval_s=3.0,
        description="un-permissioned Lambda target's event landing in its dead-letter queue",
    )
    assert any(job_id in m for m in bad_dlq_msgs), (
        f"dead-lettered event does not correlate to the triggering event: {bad_dlq_msgs}"
    )

    # Absence check: the correctly-permissioned target's OWN dead-letter queue stays empty —
    # nothing failed for it, so nothing should ever be dead-lettered there.
    good_dlq_msgs = _drain(sqs, dlq_good, wait_s=10)
    assert good_dlq_msgs == [], f"unexpected dead-letter for the working target: {good_dlq_msgs}"


_XSVC_PREFIX = "sim2real-xsvc-"


def _drain(sqs, queue_url: str, wait_s: int = 5) -> list[str]:
    out = []
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s)
    for msg in resp.get("Messages", []):
        out.append(msg["Body"])
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real:prefix", "Value": _XSVC_PREFIX.rstrip("-")},
    ]


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
            s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
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
