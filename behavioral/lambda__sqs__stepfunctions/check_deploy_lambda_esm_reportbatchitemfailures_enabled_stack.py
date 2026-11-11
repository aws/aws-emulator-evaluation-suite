"""deploy-lambda-esm-reportbatchitemfailures-enabled-stack."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-lambda-esm-reportbatchitemfailures-enabled-stack"
GROUP = "deploy-stack"
SERVICES = ["lambda", "stepfunctions", "sqs"]


# timing:real-time — visibility: 20 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """With FunctionResponseTypes ReportBatchItemFailures on an enabled mapping, only the message
    the Lambda reports as failed is redelivered, while the other message of the batch is
    processed once."""
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "SourceQueue": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {"VisibilityTimeout": 20},
                },
                "ResultsQueue": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {"MessageRetentionPeriod": 3600},
                },
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
                        "Policies": [
                            {
                                "PolicyName": "queues",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": [
                                                "sqs:ReceiveMessage",
                                                "sqs:DeleteMessage",
                                                "sqs:GetQueueAttributes",
                                            ],
                                            "Resource": {"Fn::GetAtt": ["SourceQueue", "Arn"]},
                                        },
                                        {
                                            "Effect": "Allow",
                                            "Action": "sqs:SendMessage",
                                            "Resource": {"Fn::GetAtt": ["ResultsQueue", "Arn"]},
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
                            }
                        ],
                    },
                },
                "PartialFailFn": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "Handler": "index.handler",
                        "Runtime": "python3.12",
                        "Timeout": 3,
                        "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},

                        "Environment": {
                            "Variables": {"RESULTS_QUEUE_URL": {"Ref": "ResultsQueue"}}
                        },
                        "Code": {
                            "ZipFile": (
                                "import boto3, os\n"
                                "sqs = boto3.client('sqs')\n"
                                "RESULTS_URL = os.environ['RESULTS_QUEUE_URL']\n"
                                "def handler(event, context):\n"
                                "    failures = []\n"
                                "    for rec in event['Records']:\n"
                                "        body = rec['body']\n"
                                "        sqs.send_message(QueueUrl=RESULTS_URL, MessageBody=body)\n"
                                "        if body.startswith('fail-'):\n"
                                "            failures.append({'itemIdentifier': rec['messageId']})\n"
                                "    return {'batchItemFailures': failures}\n"
                            )
                        },
                    },
                },
            },
            "Outputs": {
                "SourceQueueUrl": {"Value": {"Ref": "SourceQueue"}},
                "SourceQueueArn": {"Value": {"Fn::GetAtt": ["SourceQueue", "Arn"]}},
                "ResultsQueueUrl": {"Value": {"Ref": "ResultsQueue"}},
                "FunctionName": {"Value": {"Ref": "PartialFailFn"}},
            },
        }
    )
    # The Esm (event source mapping) is deliberately created OUTSIDE the CFN template with
    # boto3 below, not as a template resource: CreateEventSourceMapping validates synchronously
    # that the function's execution role can ReceiveMessage/DeleteMessage/GetQueueAttributes on
    # the source queue, and the inline role policy is eventually consistent -- doing it inside
    # the template turns that IAM propagation race into a CREATE_FAILED/ROLLBACK_COMPLETE of the
    # WHOLE stack. Creating it via a retried boto3 call after the stack (queue/role/function) is
    # up keeps the CFN deploy itself fast and deterministic while still exercising a stack-deployed
    # queue+role+function wired together with FunctionResponseTypes=ReportBatchItemFailures.
    stack = _deploy_cfn(ctx, template)
    source_url = stack["outputs"]["SourceQueueUrl"]
    source_arn = stack["outputs"]["SourceQueueArn"]
    results_url = stack["outputs"]["ResultsQueueUrl"]
    fn_name = stack["outputs"]["FunctionName"]

    lam = ctx.client("lambda")

    esm_id = None
    last_err: Exception | None = None
    deadline = time.monotonic() + 180.0
    while time.monotonic() < deadline:
        try:
            esm_id = lam.create_event_source_mapping(
                EventSourceArn=source_arn,
                FunctionName=fn_name,
                BatchSize=2,
                FunctionResponseTypes=["ReportBatchItemFailures"],
            )["UUID"]
            break
        except ClientError as e:
            last_err = e
            time.sleep(5.0)
    if esm_id is None:
        msg = last_err.response.get("Error", {}).get("Message", str(last_err)) if isinstance(
            last_err, ClientError
        ) else str(last_err)
        raise AssertionError(f"CreateEventSourceMapping never succeeded -- {msg}")
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=esm_id))

    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=esm_id)["State"],
        lambda s: s == "Enabled",
        timeout_s=90,
        interval_s=3.0,
        description="ESM Enabled",
    )
    # Independent read of the ESM's own config, not the value the poll loop already
    # confirmed: a target that accepts FunctionResponseTypes but silently drops it
    # (treating the mapping as an ordinary all-or-nothing one) would still reach
    # State=Enabled, so the poll above cannot catch that failure mode.
    esm_desc = lam.get_event_source_mapping(UUID=esm_id)
    assert esm_desc["State"] == "Enabled", f"expected ESM State Enabled, got {esm_desc['State']!r}"
    assert esm_desc.get("FunctionResponseTypes") == ["ReportBatchItemFailures"], (
        f"expected FunctionResponseTypes=['ReportBatchItemFailures'], got "
        f"{esm_desc.get('FunctionResponseTypes')!r}"
    )

    sqs = ctx.client("sqs")
    fail_body = f"fail-{ctx.unique_name('m')}"
    ok_body = f"ok-{ctx.unique_name('m')}"
    sqs.send_message(QueueUrl=source_url, MessageBody=fail_body)
    sqs.send_message(QueueUrl=source_url, MessageBody=ok_body)

    seen: dict[str, int] = {fail_body: 0, ok_body: 0}

    def _drain_results():
        resp = sqs.receive_message(
            QueueUrl=results_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for m in resp.get("Messages", []):
            body = m["Body"]
            if body in seen:
                seen[body] += 1
            sqs.delete_message(QueueUrl=results_url, ReceiptHandle=m["ReceiptHandle"])
        return seen[fail_body]

    _poll_until(
        _drain_results,
        lambda count: count >= 2,
        timeout_s=90,
        interval_s=3.0,
        description="failing message redelivered at least twice",
    )
    # Drain a little more in case of trailing invocations, then assert the invariant: the
    # always-failing message was retried (seen >1 time) while the always-succeeding message,
    # once processed successfully, was deleted from the source queue and not redelivered.
    for _ in range(3):
        _drain_results()
    # SQS is at-least-once even for successful deliveries, so we can't assert the succeeding
    # item was seen EXACTLY once -- only that the reported-failed item was redelivered strictly
    # more often than the one the function reported as successful (the partial-failure contract).
    assert seen[ok_body] >= 1, f"expected the succeeding item processed at least once, saw {seen}"
    assert seen[fail_body] >= 2, f"expected redelivery of failing item, saw {seen}"
    assert seen[fail_body] > seen[ok_body], f"expected failing item redelivered more than the succeeding one, saw {seen}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
