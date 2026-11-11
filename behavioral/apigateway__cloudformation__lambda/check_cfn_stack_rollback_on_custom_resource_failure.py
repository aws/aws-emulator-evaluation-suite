"""cfn-stack-rollback-on-custom-resource-failure."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-stack-rollback-on-custom-resource-failure"
GROUP = "deployment-order"
SERVICES = ["apigateway", "cloudformation", "lambda"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:e2e", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A custom resource Lambda returning FAILED rolls the stack back to ROLLBACK_COMPLETE and deletes the
    already-created sibling topic, while the same template without the forced failure completes."""
    template = json.dumps(_template())
    sns = ctx.client("sns")
    cfn = ctx.client("cloudformation")

    # --- negative: custom resource forces FAILED -> stack must roll back ---
    name = _xname(ctx, "stk")
    cfn.create_stack(
        StackName=name,
        TemplateBody=template,
        Parameters=[{"ParameterKey": "ForceFail", "ParameterValue": "true"}],
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    status = _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "CREATE_COMPLETE"},
        timeout_s=300.0,
        interval_s=5.0,
        description=f"rollback stack {name}",
    )
    if status != "ROLLBACK_COMPLETE":
        events = cfn.describe_stack_events(StackName=name)["StackEvents"]
        detail = " | ".join(
            f"{e['LogicalResourceId']}={e['ResourceStatus']}:{(e.get('ResourceStatusReason') or '')[:80]}"
            for e in events[:8]
        )
        raise AssertionError(f"expected ROLLBACK_COMPLETE, got {status}. {detail}")

    events = cfn.describe_stack_events(StackName=name)["StackEvents"]
    cr_event = next(
        (e for e in events if e["LogicalResourceId"] == "MyResource" and e["ResourceStatus"] == "CREATE_FAILED"),
        None,
    )
    assert cr_event is not None, (
        f"expected a CREATE_FAILED event for MyResource, saw statuses: "
        f"{[(e['LogicalResourceId'], e['ResourceStatus']) for e in events]}"
    )

    topic_event = next(
        (
            e
            for e in events
            if e["LogicalResourceId"] == "AlwaysTopic" and e["ResourceStatus"] == "CREATE_COMPLETE"
        ),
        None,
    )
    assert topic_event is not None, "expected the sibling SNS topic to have been created first"
    topic_arn = topic_event["PhysicalResourceId"]
    code, message = _error(lambda: sns.get_topic_attributes(TopicArn=topic_arn))
    # rollback must have deleted the successfully-created sibling resource
    assert code == "NotFound", f"expected NotFound for rolled-back topic {topic_arn}, got {code!r}"
    assert message == "Topic does not exist", (
        f"expected message 'Topic does not exist' for rolled-back topic {topic_arn}, got {message!r}"
    )

    # --- positive control: identical template, no forced failure -> succeeds and persists ---
    ok = _deploy_cfn(ctx, template, parameters={"ForceFail": "false"})
    assert ok["outputs"]["RequestType"] == "Create", (
        f"expected positive-control custom resource RequestType=Create, got {ok['outputs'].get('RequestType')!r}"
    )
    sns.get_topic_attributes(TopicArn=ok["outputs"]["TopicArn"])  # must not raise


def _template() -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"ForceFail": {"Type": "String", "Default": "false"}},
        "Resources": {
            "ExecRole": {
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
            "ProviderFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Handler": "index.handler",
                    "Runtime": "python3.12",
                    "Timeout": 30,
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Code": {"ZipFile": {"Fn::Join": ["\n", _provider_code_lines()]}},
                },
            },
            "MyResource": {
                "Type": "Custom::Sim2RealTest",
                "Properties": {
                    "ServiceToken": {"Fn::GetAtt": ["ProviderFunction", "Arn"]},
                    "Value": "x",
                    "ForceFail": {"Ref": "ForceFail"},
                },
            },
            "AlwaysTopic": {"Type": "AWS::SNS::Topic", "Properties": {}},
        },
        "Outputs": {
            "RequestType": {"Value": {"Fn::GetAtt": ["MyResource", "RequestType"]}},
            "TopicArn": {"Value": {"Ref": "AlwaysTopic"}},
        },
    }


def _provider_code_lines() -> list[str]:
    return [
        "import json",
        "import boto3",
        "import cfnresponse",
        "",
        "def handler(event, context):",
        "    props = event.get('ResourceProperties') or {}",
        "    old_props = event.get('OldResourceProperties') or {}",
        "    request_type = event['RequestType']",
        "    queue_url = props.get('QueueUrl') or old_props.get('QueueUrl')",
        "    if queue_url:",
        "        boto3.client('sqs').send_message(",
        "            QueueUrl=queue_url,",
        "            MessageBody=json.dumps({",
        "                'RequestType': request_type,",
        "                'OldValue': old_props.get('Value'),",
        "                'NewValue': props.get('Value'),",
        "            }),",
        "        )",
        "    # Always succeed Delete requests: CloudFormation invokes Delete on rollback for any",
        "    # resource that received a PhysicalResourceId, even one whose Create attempt itself",
        "    # returned FAILED — forcing failure there too would make the *rollback* fail",
        "    # (ROLLBACK_FAILED) instead of completing (ROLLBACK_COMPLETE).",
        "    if props.get('ForceFail') == 'true' and request_type != 'Delete':",
        "        cfnresponse.send(event, context, cfnresponse.FAILED, {}, 'sim2real-cr-fixed')",
        "        return",
        "    data = {'RequestType': request_type, 'NewValue': str(props.get('Value', ''))}",
        "    cfnresponse.send(event, context, cfnresponse.SUCCESS, data, 'sim2real-cr-fixed')",
    ]



_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _error(fn) -> tuple[str, str]:
    """Run ``fn`` and return the (code, message) of the ClientError it raises; a call that
    succeeds fails the check."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


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


def _deploy_cfn(
    ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0
) -> dict[str, Any]:
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
