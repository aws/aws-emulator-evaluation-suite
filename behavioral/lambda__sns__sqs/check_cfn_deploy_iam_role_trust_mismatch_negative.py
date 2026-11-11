"""cfn-deploy-iam-role-trust-mismatch-negative."""
from __future__ import annotations

import json
import time
import uuid
import zipfile
import io
from typing import Any

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "cfn-deploy-iam-role-trust-mismatch-negative"
GROUP = "deploy-iam-trust"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN stack whose Lambda role trusts ec2.amazonaws.com fails at CreateFunction and rolls back
    leaving no function and no queued message; a directly created function with a correctly
    trusted role sends to the queue (positive control)."""
    role_name = _xname(ctx, "role")
    queue_name = _xname(ctx, "queue")
    function_name = _xname(ctx, "fn")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "RoleName": {"Type": "String"},
            "QueueName": {"Type": "String"},
            "FunctionName": {"Type": "String"},
        },
        "Resources": {
            "LambdaRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": {"Ref": "RoleName"},
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                # Wrong principal: ec2, not lambda. Lambda cannot assume this role.
                                "Effect": "Allow",
                                "Principal": {"Service": "ec2.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "SendToQueue",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": ["sqs:SendMessage"],
                                        "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "Queue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": {"Ref": "QueueName"}},
            },
            "Function": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": {"Ref": "FunctionName"},
                    "Role": {"Fn::GetAtt": ["LambdaRole", "Arn"]},
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Timeout": 15,
                    "Environment": {"Variables": {"QUEUE_URL": {"Ref": "Queue"}}},
                    "Code": {
                        "ZipFile": (
                            "import boto3, os\n"
                            "sqs = boto3.client('sqs')\n"
                            "def handler(event, context):\n"
                            "    sqs.send_message(QueueUrl=os.environ['QUEUE_URL'], "
                            "MessageBody=event.get('body', 'default'))\n"
                            "    return {'ok': True}\n"
                        )
                    },
                },
            },
        },
    }

    stack_name = _xname(ctx, "stk")
    cfn = ctx.client("cloudformation")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Tags=_xsvc_tags_kv(),
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        Parameters=[
            {"ParameterKey": "RoleName", "ParameterValue": role_name},
            {"ParameterKey": "QueueName", "ParameterValue": queue_name},
            {"ParameterKey": "FunctionName", "ParameterValue": function_name},
        ],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name))

    final_status = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=240,
        interval_s=5.0,
        description=f"terminal status of stack {stack_name}",
    )
    assert final_status == "ROLLBACK_COMPLETE", (
        f"expected the mistrusted-role stack to roll back, got {final_status}"
    )

    # The specific reason, not just any failure: rollback also happens for unrelated causes.
    # CloudFormation's rollback phase emits a DELETE_SKIPPED event for the never-created Function
    # that is newer than its CREATE_FAILED event, so pick CREATE_FAILED explicitly.
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    fn_event = next(
        e for e in events if e["LogicalResourceId"] == "Function" and e["ResourceStatus"] == "CREATE_FAILED"
    )
    reason = fn_event.get("ResourceStatusReason") or ""
    # message varies: per-request Lambda request id, SDK attempt count and CloudFormation request
    # token follow the handler message, so the text before " (Service: " is asserted exactly.
    reason_text = reason.split(" (Service: ", 1)[0]
    assert reason_text == (
        'Resource handler returned message: "The role defined for the function cannot be assumed by Lambda.'
    ), f"expected the Function resource's CREATE_FAILED reason to name the unassumable role, got {reason!r}"

    # Effect absent: the function was never left around, and the queue never got a message.
    lam = ctx.client("lambda")
    code, message = _client_error(lambda: lam.get_function(FunctionName=function_name))
    assert code == "ResourceNotFoundException", f"expected the function to never exist, got error code {code!r}"
    expected = f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{function_name}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    sqs = ctx.client("sqs")
    code, message = _client_error(lambda: sqs.get_queue_url(QueueName=queue_name))
    assert code == "AWS.SimpleQueueService.NonExistentQueue", (
        f"expected the queue to never exist, got error code {code!r}"
    )
    assert message == "The specified queue does not exist.", f"got message {message!r}"

    # ---- positive control (same file): a correctly-trusted role does let the same shape of
    # function actually send to a queue. ----
    _run_positive_control(ctx)


def _run_positive_control(ctx) -> None:
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")

    role_name = _xname(ctx, "ctrl-role")
    queue_name = _xname(ctx, "ctrl-queue")
    fn_name = _xname(ctx, "ctrl-fn")

    queue_url = sqs.create_queue(QueueName=queue_name)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="send",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}]}
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="send"))

    code_bytes = io.BytesIO()
    with zipfile.ZipFile(code_bytes, "w") as zf:
        zf.writestr(
            "index.py",
            "import boto3, os\n"
            "sqs = boto3.client('sqs')\n"
            "def handler(event, context):\n"
            "    sqs.send_message(QueueUrl=os.environ['QUEUE_URL'], MessageBody=event.get('body','default'))\n"
            "    return {'ok': True}\n",
        )

    marker = f"ctrl-{uuid.uuid4().hex}"
    last_err = None
    fn_arn = None
    for _ in range(10):
        try:
            fn_arn = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": code_bytes.getvalue()},
                Timeout=15,
                Environment={"Variables": {"QUEUE_URL": queue_url}},
            )["FunctionArn"]
            break
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            time.sleep(3)
    if fn_arn is None:
        raise AssertionError(f"positive control create_function never succeeded: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))

    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=fn_name)["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=3,
        description=f"function {fn_name} to become Active",
    )

    resp = None
    deadline = time.monotonic() + 60.0
    if ctx.time_left() is not None:
        deadline = min(deadline, time.monotonic() + ctx.time_left() - 5.0)
    while time.monotonic() < deadline:
        try:
            resp = lam.invoke(
                FunctionName=fn_name, InvocationType="RequestResponse", Payload=json.dumps({"body": marker}).encode()
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceConflictException":
                time.sleep(2)
                continue
            raise
        if "FunctionError" not in resp:
            break
        time.sleep(2)
    assert resp is not None and "FunctionError" not in resp, f"positive control invoke failed: {resp}"

    def _probe():
        r = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=5, WaitTimeSeconds=5)
        for m in r.get("Messages", []):
            if m["Body"] == marker:
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
                return m
        return None

    found = _poll_until(_probe, lambda m: m is not None, timeout_s=60, interval_s=3, description="positive-control marker message")
    assert found["Body"] == marker, f"expected the positive-control message body {marker!r}, got {found['Body']!r}"


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


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _client_error(fn) -> tuple[str, str]:
    """The (Code, Message) of the ClientError fn() raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as e:
        error = e.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackNotFoundException":
            raise
        return

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError"):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
