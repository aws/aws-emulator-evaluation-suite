"""lambda-sdk-sqs-receivemessage-from-handler-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sdk-sqs-receivemessage-from-handler-positive"
GROUP = "arn-resolution"
SERVICES = ["lambda", "pipes", "sqs"]

_HANDLER_RECEIVE = '''
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    sqs = boto3.client("sqs")
    try:
        resp = sqs.receive_message(
            QueueUrl=event["queue_url"],
            MaxNumberOfMessages=1,
            WaitTimeSeconds=10,
        )
        messages = resp.get("Messages", [])
        if not messages:
            return {"ok": True, "received": 0}
        msg = messages[0]
        sqs.delete_message(QueueUrl=event["queue_url"], ReceiptHandle=msg["ReceiptHandle"])
        return {"ok": True, "received": 1, "body": msg["Body"]}
    except ClientError as exc:
        return {"ok": False, "code": exc.response["Error"]["Code"]}
'''


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda handler using boto3 sqs.receive_message()+delete_message() consumes a seeded message."""
    url, arn = _create_queue(ctx, "recvq")
    role_arn = _create_lambda_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                "Resource": arn,
            }
        ],
    )
    func_name = _create_lambda_function(ctx, role_arn, _HANDLER_RECEIVE)

    sqs = ctx.client("sqs")
    seed_body = "seed-message-" + ctx.unique_name("")
    sqs.send_message(QueueUrl=url, MessageBody=seed_body)

    result = None
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        result = _invoke_lambda(ctx, func_name, {"queue_url": url})
        assert result["ok"] is True, f"handler reported failure: {result}"
        if result.get("received") == 1:
            break
        time.sleep(2)
    assert result is not None and result.get("received") == 1, f"handler never received the seed message: {result}"
    assert result["body"] == seed_body

    # The queue's VisibilityTimeout is 5s, so a delete that silently no-ops would let the
    # message reappear well within this 15s (3x) window -- a plain receive would not tell
    # that apart from a real delete. Hold the window and also check the queue's own count.
    still_visible = False
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=3)
        if resp.get("Messages"):
            still_visible = True
            break
    assert not still_visible, "message deleted by the lambda handler is still visible on the queue"
    approx_count = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"])[
        "Attributes"
    ]["ApproximateNumberOfMessages"]
    assert approx_count == "0", f"queue still reports {approx_count} message(s) after the handler's delete"


def _create_queue(ctx, suffix: str):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name(f"sim2real-behav-{suffix}-"),
        Attributes={"VisibilityTimeout": "5"},
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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]["Arn"]
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
            ctx.on_cleanup(lambda _n=func_name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=func_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Environment={"Variables": env or {}},
            )
            created = True
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_exc = exc
            time.sleep(3)
    if not created:
        raise AssertionError(f"create_function never succeeded (role propagation?): {last_exc}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=func_name))
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


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
