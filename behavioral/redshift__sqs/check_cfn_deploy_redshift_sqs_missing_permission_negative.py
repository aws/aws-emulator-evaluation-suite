"""cfn-deploy-redshift-sqs-missing-permission-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cfn-deploy-redshift-sqs-missing-permission-negative"
GROUP = "overly-permissive"
SERVICES = ["redshift", "sqs"]


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda relay whose role lacks sqs:SendMessage fails with an AccessDenied naming SendMessage and
    its queue receives nothing from a matching Redshift event, while a correctly permitted relay
    in the same stack delivers exactly one message."""
    good_cluster = ctx.unique_name("sim2real-xsvc-cluster-good-")
    bad_cluster = ctx.unique_name("sim2real-xsvc-cluster-bad-")
    deploy = _deploy_cfn(ctx, _template(good_cluster, bad_cluster))
    outputs = deploy["outputs"]

    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    events = ctx.client("events")

    # --- deterministic, fast signal: directly invoke the under-permissioned relay -----------
    bad_payload = _redshift_envelope(bad_cluster, ctx.region)
    invoke_resp = lam.invoke(
        FunctionName=outputs["FunctionBadName"],
        InvocationType="RequestResponse",
        Payload=json.dumps(bad_payload).encode("utf-8"),
    )
    assert invoke_resp.get("FunctionError") == "Unhandled", (
        f"expected the under-permissioned relay to fail, got {invoke_resp!r}"
    )
    error_body = json.loads(invoke_resp["Payload"].read())
    error_message = error_body.get("errorMessage", "")
    assert "AccessDenied" in error_message and "SendMessage" in error_message, (
        f"expected an sqs:SendMessage AccessDenied, got {error_body!r}"
    )

    # --- full pipeline: prove the effect (message) never lands even via the real trigger ----
    put_resp = events.put_events(
        Entries=[
            {
                # PutEvents rejects Source="aws.*" from customer callers (reserved for genuine
                # AWS-service-emitted events); simulate the Redshift/CloudTrail envelope SHAPE
                # under a non-reserved source so the rule's EventPattern still matches on it.
                "Source": "sim2real.redshift",
                "DetailType": "AWS API Call via CloudTrail",
                "Detail": json.dumps(bad_payload["detail"]),
            }
        ]
    )
    assert put_resp["FailedEntryCount"] == 0, put_resp
    bad_messages = _poll_for_messages(sqs, outputs["QueueBadUrl"], bad_cluster, timeout_s=25.0)
    assert bad_messages == [], f"message unexpectedly reached QueueBad: {bad_messages}"

    # --- positive control: the correctly-permissioned relay in the SAME stack delivers -------
    good_payload = _redshift_envelope(good_cluster, ctx.region)
    put_resp = events.put_events(
        Entries=[
            {
                "Source": "sim2real.redshift",
                "DetailType": "AWS API Call via CloudTrail",
                "Detail": json.dumps(good_payload["detail"]),
            }
        ]
    )
    assert put_resp["FailedEntryCount"] == 0, put_resp
    good_messages = _poll_for_messages(
        sqs, outputs["QueueGoodUrl"], good_cluster, timeout_s=90.0
    )
    assert len(good_messages) == 1, f"expected the good relay to deliver, got {good_messages}"


def _redshift_envelope(cluster_id: str, region: str) -> dict[str, Any]:
    return {
        "version": "0",
        "id": "test",
        "detail-type": "AWS API Call via CloudTrail",
        "source": "sim2real.redshift",
        "account": "000000000000",
        "time": "2024-01-01T00:00:00Z",
        "region": region,
        "resources": [],
        "detail": {
            "eventSource": "redshift.amazonaws.com",
            "eventName": "ResumeCluster",
            "awsRegion": region,
            "requestParameters": {"clusterIdentifier": cluster_id},
        },
    }


_RELAY_CODE = """
import boto3, json, os

def handler(event, context):
    sqs = boto3.client("sqs")
    sqs.send_message(QueueUrl=os.environ["QUEUE_URL"], MessageBody=json.dumps(event))
    return {"ok": True}
"""


def _template(good_cluster: str, bad_cluster: str) -> str:
    def pattern(cluster_id: str) -> dict[str, Any]:
        return {
            "source": ["sim2real.redshift"],
            "detail-type": ["AWS API Call via CloudTrail"],
            "detail": {
                "eventSource": ["redshift.amazonaws.com"],
                "eventName": ["ResumeCluster"],
                "requestParameters": {"clusterIdentifier": [cluster_id]},
            },
        }

    doc = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "QueueGood": {"Type": "AWS::SQS::Queue"},
            "QueueBad": {"Type": "AWS::SQS::Queue"},
            "RoleGoodExec": {
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
                    "Policies": [
                        {
                            "PolicyName": "AllowSendToQueueGood",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "sqs:SendMessage",
                                        "Resource": {"Fn::GetAtt": ["QueueGood", "Arn"]},
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "RoleBadExec": {
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
            "FunctionGood": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Timeout": 15,
                    "Role": {"Fn::GetAtt": ["RoleGoodExec", "Arn"]},
                    "Code": {"ZipFile": _RELAY_CODE},
                    "Environment": {"Variables": {"QUEUE_URL": {"Ref": "QueueGood"}}},
                },
            },
            "FunctionBad": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Timeout": 15,
                    "Role": {"Fn::GetAtt": ["RoleBadExec", "Arn"]},
                    "Code": {"ZipFile": _RELAY_CODE},
                    "Environment": {"Variables": {"QUEUE_URL": {"Ref": "QueueBad"}}},
                },
            },
            "FunctionBadNoRetry": {
                "Type": "AWS::Lambda::EventInvokeConfig",
                "Properties": {
                    "FunctionName": {"Ref": "FunctionBad"},
                    "Qualifier": "$LATEST",
                    "MaximumRetryAttempts": 0,
                    "MaximumEventAgeInSeconds": 60,
                },
            },
            "RuleGood": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "State": "ENABLED",
                    "EventPattern": pattern(good_cluster),
                    "Targets": [
                        {"Id": "good", "Arn": {"Fn::GetAtt": ["FunctionGood", "Arn"]}}
                    ],
                },
            },
            "RuleBad": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "State": "ENABLED",
                    "EventPattern": pattern(bad_cluster),
                    "Targets": [
                        {"Id": "bad", "Arn": {"Fn::GetAtt": ["FunctionBad", "Arn"]}}
                    ],
                },
            },
            "PermissionGood": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "Action": "lambda:InvokeFunction",
                    "FunctionName": {"Ref": "FunctionGood"},
                    "Principal": "events.amazonaws.com",
                    "SourceArn": {"Fn::GetAtt": ["RuleGood", "Arn"]},
                },
            },
            "PermissionBad": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "Action": "lambda:InvokeFunction",
                    "FunctionName": {"Ref": "FunctionBad"},
                    "Principal": "events.amazonaws.com",
                    "SourceArn": {"Fn::GetAtt": ["RuleBad", "Arn"]},
                },
            },
        },
        "Outputs": {
            "FunctionGoodName": {"Value": {"Ref": "FunctionGood"}},
            "FunctionBadName": {"Value": {"Ref": "FunctionBad"}},
            "QueueGoodUrl": {"Value": {"Ref": "QueueGood"}},
            "QueueBadUrl": {"Value": {"Ref": "QueueBad"}},
            "RuleGoodArn": {"Value": {"Fn::GetAtt": ["RuleGood", "Arn"]}},
            "RuleBadArn": {"Value": {"Fn::GetAtt": ["RuleBad", "Arn"]}},
        },
    }
    return json.dumps(doc)


def _poll_for_messages(
    sqs, queue_url: str, cluster_id: str, *, timeout_s: float
) -> list[dict[str, Any]]:
    deadline = time.monotonic() + timeout_s
    found: list[dict[str, Any]] = []
    while time.monotonic() < deadline and not found:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10
        )
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                continue
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if body.get("detail", {}).get("requestParameters", {}).get(
                "clusterIdentifier"
            ) == cluster_id:
                found.append(body)
    return found


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
        lambda s: s
        in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
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
