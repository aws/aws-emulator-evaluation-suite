"""sfn-lambda-retry-backoff-then-catch-to-sqs."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-lambda-retry-backoff-then-catch-to-sqs"
GROUP = "task-token-lifecycle"
SERVICES = ["lambda", "stepfunctions", "sqs"]


# timing:real-time — workflow: 2 s https://docs.aws.amazon.com/step-functions/latest/dg/concepts-error-handling.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """After Retry attempts are exhausted on a permanently-failing Lambda task, the Catch
    state's native SQS integration delivers the caught failure details to a queue."""
    lambda_role_arn = _create_role(
        ctx,
        "lambda.amazonaws.com",
        [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}],
    )
    sfn_role_arn = _create_role(
        ctx,
        "states.amazonaws.com",
        [
            {
                "Effect": "Allow",
                "Action": ["lambda:InvokeFunction", "sqs:SendMessage"],
                "Resource": "*",
            }
        ],
    )
    retry_queue = _create_queue(ctx)
    failure_queue = _create_queue(ctx)

    fn_code = (
        "import json\n"
        "import boto3\n"
        "\n"
        f"RETRY_QUEUE_URL = {retry_queue['url']!r}\n"
        "\n"
        "def handler(event, context):\n"
        "    sqs = boto3.client('sqs')\n"
        "    sqs.send_message(QueueUrl=RETRY_QUEUE_URL, MessageBody=json.dumps({'invoked': True}))\n"
        "    raise Exception('boom-processing-error')\n"
    )
    fn_arn = _create_lambda_function(ctx, fn_code, lambda_role_arn, timeout=30)

    definition = {
        "StartAt": "InvokeFn",
        "States": {
            "InvokeFn": {
                "Type": "Task",
                "Resource": "arn:aws:states:::lambda:invoke",
                "Parameters": {"FunctionName": fn_arn, "Payload.$": "$"},
                "Retry": [
                    {
                        "ErrorEquals": ["States.ALL"],
                        "MaxAttempts": 2,
                        "IntervalSeconds": 1,
                        "BackoffRate": 1.0,
                    }
                ],
                "Catch": [
                    {"ErrorEquals": ["States.ALL"], "ResultPath": "$.error", "Next": "SendFailureToQueue"}
                ],
                "End": True,
            },
            "SendFailureToQueue": {
                "Type": "Task",
                "Resource": "arn:aws:states:::sqs:sendMessage",
                "Parameters": {
                    "QueueUrl": failure_queue["url"],
                    "MessageBody.$": "States.JsonToString($.error)",
                },
                "End": True,
            },
        },
    }
    sm_arn = _create_state_machine(ctx, definition, sfn_role_arn)
    exec_arn = _start_execution(ctx, sm_arn, {})
    desc = _wait_execution_terminal(ctx, exec_arn, timeout_s=90)

    assert desc["status"] == "SUCCEEDED", f"expected SUCCEEDED (caught), got {desc['status']}: {desc.get('error')}"

    # Retry exhausted MaxAttempts=2 before falling into Catch: initial + 2 retries = 3 invocations.
    retries = _drain_queue(ctx, retry_queue["url"], min_count=3, timeout_s=30)
    assert len(retries) == 3, f"expected exactly 3 invocations (initial + 2 retries), got {len(retries)}"

    # The Catch fired exactly once, delivering the failure details to the failure queue.
    failures = _drain_queue(ctx, failure_queue["url"], min_count=1, timeout_s=30)
    assert len(failures) == 1, f"expected exactly 1 failure message, got {len(failures)}"
    assert "boom-processing-error" in failures[0], failures[0]


# ===== helpers =====
def _zip_bytes(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_role(ctx, principal, extra_statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "*",
        }
    ] + extra_statements
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_lambda_function(ctx, code, role_arn, timeout=30):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    zip_bytes = _zip_bytes(code)
    resp = None
    deadline = time.monotonic() + 60.0
    if ctx.time_left() is not None:
        deadline = min(deadline, time.monotonic() + ctx.time_left() - 5.0)
    while True:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValueException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return resp["FunctionArn"]


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-sm-")
    deadline = time.monotonic() + 60.0
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD"
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                last_err = e
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise AssertionError(f"could not create state machine after IAM propagation wait: {last_err}")
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _start_execution(ctx, sm_arn, input_dict):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-exec-")
    resp = sfn.start_execution(stateMachineArn=sm_arn, name=name, input=json.dumps(input_dict))
    return resp["executionArn"]


def _wait_execution_terminal(ctx, exec_arn, timeout_s=90, poll_s=3):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    desc = sfn.describe_execution(executionArn=exec_arn)
    while desc["status"] == "RUNNING" and time.monotonic() < deadline:
        time.sleep(poll_s)
        desc = sfn.describe_execution(executionArn=exec_arn)
    if desc["status"] == "RUNNING":
        raise AssertionError(f"execution still RUNNING after {timeout_s}s")
    return desc


def _create_queue(ctx):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"url": url}


def _drain_queue(ctx, queue_url, min_count, timeout_s=30):
    # Runs the full window rather than returning as soon as min_count is reached, so an
    # exact-count assertion on the result can actually observe a straggler over-delivery
    # instead of being capped at min_count by construction.
    sqs = ctx.client("sqs")
    bodies = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            bodies.append(m["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    if len(bodies) < min_count:
        raise AssertionError(f"expected at least {min_count} message(s) on {queue_url}, got {len(bodies)}")
    return bodies


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
