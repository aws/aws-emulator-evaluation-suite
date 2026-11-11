"""cfn-deploy-eventbridge-rule-missing-lambda-permission-not-invoked."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-eventbridge-rule-missing-lambda-permission-not-invoked"
GROUP = "overly-permissive"
SERVICES = ["cloudfront", "events"]


@tags("axis:negative-delivery", "cap:c3", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Of two Lambda targets on a CFN-deployed EventBridge rule, a matching event invokes the one whose resource policy
    grants events.amazonaws.com lambda:InvokeFunction and never the one without it; after the same permission is
    added to the second, the same event invokes it too."""
    sqs = ctx.client("sqs")
    events = ctx.client("events")
    lam = ctx.client("lambda")

    stack = _deploy_cfn(ctx, json.dumps(_template()))
    queue_url = stack["outputs"]["QueueUrl"]
    bad_fn_name = stack["outputs"]["BadFnName"]
    rule_arn = stack["outputs"]["RuleArn"]

    events.put_events(
        Entries=[
            {
                "Source": "sim2real.cloudfront-automation",
                "DetailType": "DistributionConfigChanged",
                "Detail": json.dumps({"marker": _xname(ctx, "trg")}),
            }
        ]
    )

    total: dict[str, int] = {}

    def _drain(duration_s: float) -> dict[str, int]:
        deadline = time.monotonic() + duration_s
        while time.monotonic() < deadline:
            resp = sqs.receive_message(
                QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
            )
            for m in resp.get("Messages", []):
                body = json.loads(m["Body"])
                total[body["fn"]] = total.get(body["fn"], 0) + 1
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
        return dict(total)

    _poll_until(
        lambda: _drain(5),
        lambda t: t.get("good", 0) >= 1,
        timeout_s=60,
        interval_s=1,
        description="positive control: target WITH the events.amazonaws.com resource-policy "
        "statement is invoked",
    )
    assert total.get("good", 0) >= 1, f"positive-control target was never invoked: {total!r}"

    # keep draining for a further window to give a stray, delayed delivery to the unpermissioned
    # target every reasonable chance to show up before asserting its absence
    _drain(20)
    assert total.get("bad", 0) == 0, (
        "the Lambda target lacking an events.amazonaws.com resource-policy statement was "
        f"invoked anyway: {total!r}"
    )

    # Restore: grant BadFn the resource-policy statement GoodFn has, for the same rule; the same
    # event then reaches it, so the missing permission alone withheld the invocation.
    lam.add_permission(
        FunctionName=bad_fn_name,
        StatementId="AllowEventsAfterFix",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )
    ctx.on_cleanup(
        lambda: lam.remove_permission(
            FunctionName=bad_fn_name, StatementId="AllowEventsAfterFix"
        )
    )

    events.put_events(
        Entries=[
            {
                "Source": "sim2real.cloudfront-automation",
                "DetailType": "DistributionConfigChanged",
                "Detail": json.dumps({"marker": _xname(ctx, "trg")}),
            }
        ]
    )
    _poll_until(
        lambda: _drain(5),
        lambda t: t.get("bad", 0) >= 1,
        timeout_s=60,
        interval_s=1,
        description="restore control: after granting the identical permission, the "
        "previously-withheld target is invoked",
    )
    assert total.get("bad", 0) >= 1, (
        f"target still not invoked after granting the missing permission: {total!r}"
    )


def _template() -> dict[str, Any]:
    lambda_code = (
        "import json, os\n"
        "import boto3\n\n"
        "def handler(event, context):\n"
        "    sqs = boto3.client('sqs')\n"
        "    sqs.send_message(\n"
        "        QueueUrl=os.environ['QUEUE_URL'],\n"
        "        MessageBody=json.dumps({'fn': os.environ['FN_TAG'], 'detail_type': event.get('detail-type')}),\n"
        "    )\n"
        "    return {'ok': True}\n"
    )
    exec_role = {
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
            "Policies": [
                {
                    "PolicyName": "send-and-log",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "logs:CreateLogGroup",
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents",
                                ],
                                "Resource": "*",
                            },
                            {
                                "Effect": "Allow",
                                "Action": "sqs:SendMessage",
                                "Resource": {"Fn::GetAtt": ["Marker", "Arn"]},
                            },
                        ],
                    },
                }
            ],
        },
    }

    def _fn(tag: str) -> dict[str, Any]:
        return {
            "Type": "AWS::Lambda::Function",
            "Properties": {
                "Runtime": "python3.12",
                "Handler": "index.handler",
                "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                "Timeout": 30,
                "Environment": {
                    "Variables": {"QUEUE_URL": {"Ref": "Marker"}, "FN_TAG": tag}
                },
                "Code": {"ZipFile": lambda_code},
            },
        }

    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Marker": {"Type": "AWS::SQS::Queue"},
            "ExecRole": exec_role,
            "GoodFn": _fn("good"),
            "BadFn": _fn("bad"),
            "TriggerRule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "EventPattern": {
                        "source": ["sim2real.cloudfront-automation"],
                        "detail-type": ["DistributionConfigChanged"],
                    },
                    "Targets": [
                        {"Id": "good", "Arn": {"Fn::GetAtt": ["GoodFn", "Arn"]}},
                        {"Id": "bad", "Arn": {"Fn::GetAtt": ["BadFn", "Arn"]}},
                    ],
                },
            },
            # Only GoodFn gets a resource-policy statement letting events.amazonaws.com invoke
            # it. BadFn is deliberately left without one -- the ONE thing this check breaks.
            "GoodPermission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "Action": "lambda:InvokeFunction",
                    "FunctionName": {"Ref": "GoodFn"},
                    "Principal": "events.amazonaws.com",
                    "SourceArn": {"Fn::GetAtt": ["TriggerRule", "Arn"]},
                },
            },
        },
        "Outputs": {
            "QueueUrl": {"Value": {"Ref": "Marker"}},
            "BadFnName": {"Value": {"Ref": "BadFn"}},
            "RuleArn": {"Value": {"Fn::GetAtt": ["TriggerRule", "Arn"]}},
        },
    }


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
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError") or (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" not in exc.response["Error"]["Message"]
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
    template_body = template.read_text() if hasattr(template, "read_text") else template
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
