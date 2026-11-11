"""cfn-deploy-redshift-sqs-role-trust-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-redshift-sqs-role-trust-positive"
GROUP = "arn-resolution"
SERVICES = ["redshift", "sqs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """The role a stack creates trusting sqs.amazonaws.com has the GetAtt-resolved ARN and exactly the
    declared trust statement, and the stack's rule delivers one matching PauseCluster event to SQS
    with its cluster id."""
    cluster_id = ctx.unique_name("sim2real-xsvc-cluster-")
    deploy = _deploy_cfn(ctx, _template(cluster_id))
    outputs = deploy["outputs"]

    iam = ctx.client("iam")
    role_name = outputs["RoleName"]
    role_arn = outputs["RoleArn"]
    role = iam.get_role(RoleName=role_name)["Role"]
    assert role["Arn"] == role_arn, "GetAtt-resolved RoleArn output doesn't match live role ARN"

    trust_doc = role["AssumeRolePolicyDocument"]
    statements = trust_doc["Statement"]
    assert len(statements) == 1, f"expected exactly 1 trust statement, got {statements!r}"
    stmt = statements[0]
    assert stmt["Effect"] == "Allow", f"expected Effect=Allow, got {stmt['Effect']!r}"
    assert stmt["Principal"]["Service"] == "sqs.amazonaws.com", (
        f"expected Principal.Service=sqs.amazonaws.com, got {stmt['Principal']!r}"
    )
    assert stmt["Action"] == "sts:AssumeRole", f"expected Action=sts:AssumeRole, got {stmt['Action']!r}"

    queue_url = outputs["QueueUrl"]
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    detail = {
        "eventSource": "redshift.amazonaws.com",
        "eventName": "PauseCluster",
        "awsRegion": ctx.region,
        "requestParameters": {"clusterIdentifier": cluster_id},
    }
    put_resp = events.put_events(
        Entries=[
            {
                # PutEvents rejects Source="aws.*" from customers;
                # simulate the Redshift/CloudTrail envelope shape under a non-reserved source.
                "Source": "sim2real.redshift",
                "DetailType": "AWS API Call via CloudTrail",
                "Detail": json.dumps(detail),
            }
        ]
    )
    assert put_resp["FailedEntryCount"] == 0, put_resp

    messages = _poll_for_messages(sqs, queue_url, cluster_id, timeout_s=60.0)
    assert len(messages) == 1, f"expected exactly 1 matching message, got {len(messages)}"
    body = messages[0]
    assert body["source"] == "sim2real.redshift", f"expected source=sim2real.redshift, got {body['source']!r}"
    assert body["detail"]["eventName"] == "PauseCluster", (
        f"expected detail.eventName=PauseCluster, got {body['detail']['eventName']!r}"
    )
    assert body["detail"]["requestParameters"]["clusterIdentifier"] == cluster_id, (
        f"expected clusterIdentifier={cluster_id!r}, "
        f"got {body['detail']['requestParameters']['clusterIdentifier']!r}"
    )


def _template(cluster_id: str) -> str:
    pattern = {
        "source": ["sim2real.redshift"],
        "detail-type": ["AWS API Call via CloudTrail"],
        "detail": {
            "eventSource": ["redshift.amazonaws.com"],
            "eventName": ["PauseCluster"],
            "requestParameters": {"clusterIdentifier": [cluster_id]},
        },
    }
    doc = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "EventQueue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"MessageRetentionPeriod": 3600},
            },
            "RedshiftRule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "State": "ENABLED",
                    "EventPattern": pattern,
                    "Targets": [
                        {"Id": "SqsTarget", "Arn": {"Fn::GetAtt": ["EventQueue", "Arn"]}}
                    ],
                },
            },
            "EventQueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "EventQueue"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AllowEventBridge",
                                "Effect": "Allow",
                                "Principal": {"Service": "events.amazonaws.com"},
                                "Action": "sqs:SendMessage",
                                "Resource": {"Fn::GetAtt": ["EventQueue", "Arn"]},
                                "Condition": {
                                    "ArnEquals": {
                                        "aws:SourceArn": {
                                            "Fn::GetAtt": ["RedshiftRule", "Arn"]
                                        }
                                    }
                                },
                            }
                        ],
                    },
                },
            },
            "SqsTrustRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "sqs.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    }
                },
            },
        },
        "Outputs": {
            "QueueUrl": {"Value": {"Ref": "EventQueue"}},
            "QueueArn": {"Value": {"Fn::GetAtt": ["EventQueue", "Arn"]}},
            "RuleArn": {"Value": {"Fn::GetAtt": ["RedshiftRule", "Arn"]}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["SqsTrustRole", "Arn"]}},
            "RoleName": {"Value": {"Ref": "SqsTrustRole"}},
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
