"""cfn-deploy-redshift-serverless-workgroup-sqs-notification-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-redshift-serverless-workgroup-sqs-notification-positive"
GROUP = "deployment-order"
SERVICES = ["redshift", "sqs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack holding a Redshift Serverless namespace and workgroup plus an EventBridge rule and SQS
    queue delivers a matching workgroup event, injected with PutEvents, with its source and
    workgroup name intact."""
    queue_name = _xname(ctx, "q")
    rule_name = _xname(ctx, "rule")
    namespace_name = _xname(ctx, "ns")
    workgroup_name = _xname(ctx, "wg")
    redshift_source = "sim2real.redshift-serverless"

    template = {
        "Resources": {
            "Queue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": queue_name},
            },
            "Rule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "Name": rule_name,
                    "EventPattern": {"source": [redshift_source]},
                    "Targets": [
                        {"Id": "sqs-target", "Arn": {"Fn::GetAtt": ["Queue", "Arn"]}}
                    ],
                },
            },
            "QueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "Queue"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "events.amazonaws.com"},
                                "Action": "sqs:SendMessage",
                                "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                                "Condition": {
                                    "ArnEquals": {
                                        "aws:SourceArn": {"Fn::GetAtt": ["Rule", "Arn"]}
                                    }
                                },
                            }
                        ],
                    },
                },
            },
            "Namespace": {
                "Type": "AWS::RedshiftServerless::Namespace",
                "Properties": {
                    "NamespaceName": namespace_name,
                    "AdminUsername": "sim2realadmin",
                    "AdminUserPassword": "Sim2RealPwd123",
                    "DbName": "sim2realdb",
                },
            },
            "Workgroup": {
                "Type": "AWS::RedshiftServerless::Workgroup",
                "Properties": {
                    "WorkgroupName": workgroup_name,
                    "NamespaceName": {"Ref": "Namespace"},
                    "BaseCapacity": 8,
                    "PubliclyAccessible": False,
                },
            },
        },
        "Outputs": {
            "QueueUrl": {"Value": {"Ref": "Queue"}},
        },
    }

    stack = _deploy_cfn(ctx, json.dumps(template), timeout_s=900.0)
    queue_url = stack["outputs"]["QueueUrl"]

    events = ctx.client("events")
    put_resp = events.put_events(
        Entries=[
            {
                "Source": redshift_source,
                "DetailType": "Redshift Serverless Workgroup Event",
                "Detail": json.dumps(
                    {"workgroupName": workgroup_name, "eventId": "SIM2REAL-WORKGROUP-EVENT"}
                ),
            }
        ]
    )
    assert put_resp["FailedEntryCount"] == 0, f"put_events rejected the entry: {put_resp}"

    sqs = ctx.client("sqs")
    message = _poll_until(
        lambda: sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=10
        ).get("Messages"),
        lambda msgs: bool(msgs),
        timeout_s=120.0,
        interval_s=5.0,
        description="workgroup event delivered to sqs",
    )[0]
    body = json.loads(message["Body"])
    assert body["source"] == redshift_source, f"expected source={redshift_source!r}, got {body.get('source')!r}"
    # EventBridge->SQS delivers `detail` as the already-decoded JSON object, not a re-encoded
    # string, so a second json.loads would raise TypeError.
    delivered_name = body["detail"]["workgroupName"]
    assert delivered_name == workgroup_name, f"expected workgroupName={workgroup_name!r}, got {delivered_name!r}"


_XSVC_PREFIX = "sim2real-xsvc-"


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
    return {"sim2real:managed": "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


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
        timeout_s=600,
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
