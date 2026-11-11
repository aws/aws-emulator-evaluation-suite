"""cfn-deploy-redshift-sqs-queue-policy-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cfn-deploy-redshift-sqs-queue-policy-negative"
GROUP = "overly-permissive"
SERVICES = ["redshift", "sqs"]


@tags("axis:negative-delivery", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A queue whose policy names only the other rule's SourceArn never receives the event; it lands
    once in that rule's dead-letter queue with error code NO_PERMISSIONS, while the correctly
    scoped rule and queue in the same stack deliver it."""
    good_cluster = ctx.unique_name("sim2real-xsvc-cluster-good-")
    bad_cluster = ctx.unique_name("sim2real-xsvc-cluster-bad-")
    deploy = _deploy_cfn(ctx, _template(good_cluster, bad_cluster))
    outputs = deploy["outputs"]

    events = ctx.client("events")
    sqs = ctx.client("sqs")

    # --- trigger the misconfigured pipeline: EventBridge denies delivery to QueueBad --------
    bad_detail = {
        "eventSource": "redshift.amazonaws.com",
        "eventName": "PauseCluster",
        "awsRegion": ctx.region,
        "requestParameters": {"clusterIdentifier": bad_cluster},
    }
    put_resp = events.put_events(
        Entries=[
            {
                # PutEvents rejects Source="aws.*" from customer callers; simulate the
                # Redshift/CloudTrail envelope SHAPE under a non-reserved custom source.
                "Source": "sim2real.redshift",
                "DetailType": "AWS API Call via CloudTrail",
                "Detail": json.dumps(bad_detail),
            }
        ]
    )
    assert put_resp["FailedEntryCount"] == 0, put_resp

    dlq_messages = _poll_for_dlq_messages(
        sqs, outputs["DlqUrl"], bad_cluster, timeout_s=60.0
    )
    assert len(dlq_messages) == 1, f"expected exactly 1 DLQ message, got {len(dlq_messages)}"
    error_code = dlq_messages[0]["attrs"].get("ERROR_CODE", {}).get("StringValue")
    assert error_code == "NO_PERMISSIONS", f"unexpected DLQ error code: {error_code!r}"

    bad_queue_messages = _poll_for_body_matches(
        sqs, outputs["QueueBadUrl"], bad_cluster, timeout_s=10.0
    )
    assert bad_queue_messages == [], f"message unexpectedly reached QueueBad: {bad_queue_messages}"

    # --- positive control: the correctly-scoped rule/queue pair in the SAME stack delivers ---
    good_detail = {
        "eventSource": "redshift.amazonaws.com",
        "eventName": "PauseCluster",
        "awsRegion": ctx.region,
        "requestParameters": {"clusterIdentifier": good_cluster},
    }
    put_resp = events.put_events(
        Entries=[
            {
                "Source": "sim2real.redshift",
                "DetailType": "AWS API Call via CloudTrail",
                "Detail": json.dumps(good_detail),
            }
        ]
    )
    assert put_resp["FailedEntryCount"] == 0, put_resp
    good_messages = _poll_for_body_matches(
        sqs, outputs["QueueGoodUrl"], good_cluster, timeout_s=60.0
    )
    assert len(good_messages) == 1, f"expected the good pipeline to deliver, got {good_messages}"


def _template(good_cluster: str, bad_cluster: str) -> str:
    def pattern(cluster_id: str) -> dict[str, Any]:
        return {
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
            "QueueGood": {"Type": "AWS::SQS::Queue"},
            "QueueBad": {"Type": "AWS::SQS::Queue"},
            "Dlq": {"Type": "AWS::SQS::Queue"},
            "RuleGood": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "State": "ENABLED",
                    "EventPattern": pattern(good_cluster),
                    "Targets": [
                        {"Id": "good-target", "Arn": {"Fn::GetAtt": ["QueueGood", "Arn"]}}
                    ],
                },
            },
            "RuleBad": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "State": "ENABLED",
                    "EventPattern": pattern(bad_cluster),
                    "Targets": [
                        {
                            "Id": "bad-target",
                            "Arn": {"Fn::GetAtt": ["QueueBad", "Arn"]},
                            "DeadLetterConfig": {"Arn": {"Fn::GetAtt": ["Dlq", "Arn"]}},
                        }
                    ],
                },
            },
            "QueueGoodPolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "QueueGood"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AllowEventBridge",
                                "Effect": "Allow",
                                "Principal": {"Service": "events.amazonaws.com"},
                                "Action": "sqs:SendMessage",
                                "Resource": {"Fn::GetAtt": ["QueueGood", "Arn"]},
                                "Condition": {
                                    "ArnEquals": {
                                        "aws:SourceArn": {"Fn::GetAtt": ["RuleGood", "Arn"]}
                                    }
                                },
                            }
                        ],
                    },
                },
            },
            # Deliberately scoped to RuleGood's ARN instead of RuleBad's -- the actual sender
            # (RuleBad) is never authorized, so EventBridge's delivery to QueueBad is denied.
            "QueueBadPolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "QueueBad"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AllowEventBridgeWrongSource",
                                "Effect": "Allow",
                                "Principal": {"Service": "events.amazonaws.com"},
                                "Action": "sqs:SendMessage",
                                "Resource": {"Fn::GetAtt": ["QueueBad", "Arn"]},
                                "Condition": {
                                    "ArnEquals": {
                                        "aws:SourceArn": {"Fn::GetAtt": ["RuleGood", "Arn"]}
                                    }
                                },
                            }
                        ],
                    },
                },
            },
            "DlqPolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "Dlq"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AllowEventBridgeDlq",
                                "Effect": "Allow",
                                "Principal": {"Service": "events.amazonaws.com"},
                                "Action": "sqs:SendMessage",
                                "Resource": {"Fn::GetAtt": ["Dlq", "Arn"]},
                                "Condition": {
                                    "ArnEquals": {
                                        "aws:SourceArn": {"Fn::GetAtt": ["RuleBad", "Arn"]}
                                    }
                                },
                            }
                        ],
                    },
                },
            },
        },
        "Outputs": {
            "QueueGoodUrl": {"Value": {"Ref": "QueueGood"}},
            "QueueBadUrl": {"Value": {"Ref": "QueueBad"}},
            "DlqUrl": {"Value": {"Ref": "Dlq"}},
            "RuleGoodArn": {"Value": {"Fn::GetAtt": ["RuleGood", "Arn"]}},
            "RuleBadArn": {"Value": {"Fn::GetAtt": ["RuleBad", "Arn"]}},
        },
    }
    return json.dumps(doc)


def _poll_for_body_matches(
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


def _poll_for_dlq_messages(
    sqs, queue_url: str, cluster_id: str, *, timeout_s: float
) -> list[dict[str, Any]]:
    """DLQ messages carry the original event as the body and EventBridge's failure metadata
    (RULE_ARN, TARGET_ARN, ERROR_CODE, ...) as SQS message attributes."""
    deadline = time.monotonic() + timeout_s
    found: list[dict[str, Any]] = []
    while time.monotonic() < deadline and not found:
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=10,
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = {}
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if body.get("detail", {}).get("requestParameters", {}).get(
                "clusterIdentifier"
            ) == cluster_id:
                found.append({"body": body, "attrs": msg.get("MessageAttributes", {})})
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
