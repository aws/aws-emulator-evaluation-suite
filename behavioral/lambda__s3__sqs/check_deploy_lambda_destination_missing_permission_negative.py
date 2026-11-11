"""deploy-lambda-destination-missing-permission-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-lambda-destination-missing-permission-negative"
GROUP = "overly-permissive"
SERVICES = ["lambda", "s3", "sqs"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:eventing", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """Lambda checks an OnFailure destination's sqs:SendMessage permission when the EventInvokeConfig
    is created: a stack whose role lacks it fails to deploy, while an identical stack with it deploys
    and delivers the failed invocation's record to the queue (positive control)."""
    control_fn_name = ctx.unique_name("sim2real-xsvc-fn-ctl-")
    broken_fn_name = ctx.unique_name("sim2real-xsvc-fn-brk-")

    control_template = _build_template(control_fn_name, grant_send=True)
    control_stack = _deploy_cfn(ctx, control_template, stack_name=ctx.unique_name("sim2real-xsvc-stk-ctl-"))

    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    control_queue_url = control_stack["outputs"]["DestQueueUrl"]
    control_fn = control_stack["outputs"]["FunctionName"]

    lam.invoke(FunctionName=control_fn, InvocationType="Event", Payload=json.dumps({"id": "c1"}).encode())

    # Positive control: the role has permission to send to its own destination queue, so the
    # failure record for the genuinely-failing invocation is delivered.
    control_msg = _poll_until(
        lambda: _receive_one(sqs, control_queue_url),
        lambda m: m is not None,
        timeout_s=90,
        interval_s=3.0,
        description="control OnFailure delivery",
    )
    control_body = json.loads(control_msg["Body"])
    assert control_body["requestContext"]["condition"] == "RetriesExhausted", (
        f"expected the control's OnFailure record to report RetriesExhausted, got: {control_body['requestContext']!r}"
    )
    assert "c1" in control_body["responsePayload"]["errorMessage"], (
        f"expected the control's failure payload to echo invocation id 'c1', got: {control_body['responsePayload']!r}"
    )

    # Negative: the same shape of stack, but the role has no sqs:SendMessage on its own
    # destination queue. Real AWS rejects the EventInvokeConfig at *deploy time* — the stack
    # never reaches CREATE_COMPLETE, and no OnFailure wiring is ever established.
    broken_template = _build_template(broken_fn_name, grant_send=False)
    result = _deploy_cfn_expect_failure(ctx, broken_template, stack_name=ctx.unique_name("sim2real-xsvc-stk-brk-"))
    assert result["status"] in {"ROLLBACK_COMPLETE", "CREATE_FAILED", "ROLLBACK_FAILED"}, (
        f"expected the deploy to fail without sqs:SendMessage, got status={result['status']}"
    )
    reason = result["reason"].lower()
    assert "sendmessage" in reason or "permission" in reason, (
        f"expected a SendMessage-permission failure reason, got: {result['reason']!r}"
    )


def _receive_one(sqs, queue_url, wait_s=5):
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=wait_s)
    msgs = resp.get("Messages", [])
    if not msgs:
        return None
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msgs[0]["ReceiptHandle"])
    return msgs[0]


# ===== helpers =====
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


def _xsvc_resource_tags() -> dict:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list:
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
            # DescribeStacks answers ValidationError "Stack ... does not exist" once the stack is gone.
            if exc.response.get("Error", {}).get("Code") == "ValidationError" and "does not exist" in str(exc):
                return "GONE"
            raise

    status = _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "DELETE_FAILED", "GONE"},
        timeout_s=120,
        interval_s=2.0,
        description=f"delete stack {stack_name}",
    )
    if status == "DELETE_FAILED":
        raise AssertionError(f"stack {stack_name} ended DELETE_FAILED")


def _stack_failure_reason(cfn, name: str) -> str:
    try:
        for e in cfn.describe_stack_events(StackName=name)["StackEvents"][:30]:
            if "FAILED" in e.get("ResourceStatus", ""):
                r = e.get("ResourceStatusReason", "")
                if r and "cancelled" not in r.lower():
                    return f"{e['LogicalResourceId']}: {r}"
    except ClientError:
        pass
    return ""


def _create_and_wait(ctx, cfn, name: str, template_body: str, capabilities, parameters, timeout_s: float) -> str:
    ctx.verify_account_safety()
    kwargs: dict = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    cfn.create_stack(**kwargs)
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0):
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    status = _create_and_wait(ctx, cfn, name, template_body, capabilities, parameters, timeout_s)
    if status != "CREATE_COMPLETE":
        reason = _stack_failure_reason(cfn, name)
        raise AssertionError(reason[:300] or f"status={status}")
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "outputs": outputs}


def _deploy_cfn_expect_failure(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0):
    """Like _deploy_cfn, but the caller expects (and asserts on) a failed deployment."""
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    status = _create_and_wait(ctx, cfn, name, template_body, capabilities, parameters, timeout_s)
    reason = "" if status == "CREATE_COMPLETE" else _stack_failure_reason(cfn, name)
    return {"status": status, "reason": reason}


def _build_template(fn_name: str, *, grant_send: bool) -> str:
    fail_code = "def handler(event, context):\n    raise Exception('boom-' + event.get('id', ''))\n"

    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "*",
        }
    ]
    if grant_send:
        statements.append(
            {
                "Effect": "Allow",
                "Action": "sqs:SendMessage",
                "Resource": {"Fn::GetAtt": ["DestQueue", "Arn"]},
            }
        )

    doc = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "DestQueue": {"Type": "AWS::SQS::Queue"},
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
                        {"PolicyName": "exec", "PolicyDocument": {"Version": "2012-10-17", "Statement": statements}}
                    ],
                },
            },
            "Function": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": fn_name,
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Timeout": 10,
                    "Code": {"ZipFile": fail_code},
                },
            },
            "OnFailureConfig": {
                "Type": "AWS::Lambda::EventInvokeConfig",
                "Properties": {
                    "FunctionName": {"Ref": "Function"},
                    "Qualifier": "$LATEST",
                    "MaximumRetryAttempts": 0,
                    "DestinationConfig": {"OnFailure": {"Destination": {"Fn::GetAtt": ["DestQueue", "Arn"]}}},
                },
            },
        },
        "Outputs": {
            "DestQueueUrl": {"Value": {"Ref": "DestQueue"}},
            "FunctionName": {"Value": {"Ref": "Function"}},
        },
    }
    return json.dumps(doc)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

