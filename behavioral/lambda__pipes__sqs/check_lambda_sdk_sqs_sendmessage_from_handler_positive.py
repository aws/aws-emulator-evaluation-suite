"""lambda-sdk-sqs-sendmessage-from-handler-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "lambda-sdk-sqs-sendmessage-from-handler-positive"
GROUP = "arn-resolution"
SERVICES = ["lambda", "pipes", "sqs"]

_HANDLER_SEND = '''
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    sqs = boto3.client("sqs")
    try:
        resp = sqs.send_message(QueueUrl=event["queue_url"], MessageBody=event["body"])
        return {"ok": True, "message_id": resp["MessageId"]}
    except ClientError as exc:
        return {"ok": False, "code": exc.response["Error"]["Code"]}
'''


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda handler using boto3 sqs.send_message() delivers a message visible via ReceiveMessage."""
    url, arn = _create_queue(ctx, "sendq")
    role_arn = _create_lambda_role(
        ctx, [{"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": arn}]
    )
    func_name = _create_lambda_function(ctx, role_arn, _HANDLER_SEND)

    body_text = "hello-from-lambda-" + ctx.unique_name("")
    result = _invoke_lambda(ctx, func_name, {"queue_url": url, "body": body_text})
    assert result["ok"] is True, f"handler reported failure: {result}"
    assert "message_id" in result, f"handler response missing message_id: {result}"

    sqs = ctx.client("sqs")
    deadline = time.monotonic() + 30
    received = None
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        msgs = resp.get("Messages", [])
        if msgs:
            received = msgs[0]
            sqs.delete_message(QueueUrl=url, ReceiptHandle=received["ReceiptHandle"])
            break
    assert received is not None, "message sent by lambda handler never appeared on the queue"
    assert received["Body"] == body_text, f"expected body {body_text!r}, got {received['Body']!r}"


_RESOURCE_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _create_queue(ctx, suffix: str):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name(f"sim2real-behav-{suffix}-"), tags=_RESOURCE_TAGS
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_lambda_role(ctx, extra_statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": k, "Value": v} for k, v in _RESOURCE_TAGS.items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
            *extra_statements,
        ],
    }
    policy_name = "inline-policy"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_lambda_function(ctx, role_arn, code_str, env=None, timeout=30):
    lam = ctx.client("lambda")
    func_name = ctx.unique_name("sim2real-behav-fn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", code_str)
    zip_bytes = buf.getvalue()
    last_exc = None
    deadline = time.monotonic() + 90
    created = False
    while time.monotonic() < deadline:
        try:
            lam.create_function(
                FunctionName=func_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Environment={"Variables": env or {}},
                Tags=dict(_RESOURCE_TAGS),
            )
            created = True
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_exc = exc
            time.sleep(3)
    if not created:
        raise AssertionError(f"create_function never succeeded (role propagation?): {last_exc}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=func_name))
    # A first invoke auto-creates /aws/lambda/<name>, which survives function deletion.
    ctx.on_cleanup(
        lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{func_name}")
    )
    lam.get_waiter("function_active_v2").wait(FunctionName=func_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return func_name


def _invoke_lambda(ctx, func_name, payload):
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=func_name,
        Payload=json.dumps(payload).encode("utf-8"),
        InvocationType="RequestResponse",
    )
    assert "FunctionError" not in resp, f"lambda invocation raised unhandled error: {resp}"
    return json.loads(resp["Payload"].read())


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
