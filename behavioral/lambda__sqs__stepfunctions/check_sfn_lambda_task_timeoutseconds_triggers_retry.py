"""sfn-lambda-task-timeoutseconds-triggers-retry."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-lambda-task-timeoutseconds-triggers-retry"
GROUP = "task-token-lifecycle"
SERVICES = ["lambda", "stepfunctions", "sqs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """TimeoutSeconds elapsing on a synchronous Lambda task raises States.Timeout, which
    the configured Retry policy catches and re-invokes the function for."""
    lambda_role_arn = _create_role(
        ctx,
        "lambda.amazonaws.com",
        [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}],
    )
    sfn_role_arn = _create_role(
        ctx,
        "states.amazonaws.com",
        [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": "*"}],
    )

    ping_queue = _create_queue(ctx)

    fn_code = (
        "import json\n"
        "import time\n"
        "import boto3\n"
        "\n"
        f"QUEUE_URL = {ping_queue['url']!r}\n"
        "\n"
        "def handler(event, context):\n"
        "    sqs = boto3.client('sqs')\n"
        "    sqs.send_message(QueueUrl=QUEUE_URL, MessageBody=json.dumps({'invoked': True}))\n"
        "    time.sleep(8)\n"
        "    return {'done': True}\n"
    )
    # The task's TimeoutSeconds (5s) is shorter than the function's own sleep (8s), so
    # every attempt is abandoned by Step Functions before the function itself returns.
    fn_arn = _create_lambda_function(ctx, fn_code, lambda_role_arn, timeout=30)

    definition = {
        "StartAt": "InvokeFn",
        "States": {
            "InvokeFn": {
                "Type": "Task",
                "Resource": "arn:aws:states:::lambda:invoke",
                "Parameters": {"FunctionName": fn_arn, "Payload.$": "$"},
                "TimeoutSeconds": 5,
                "Retry": [
                    {
                        "ErrorEquals": ["States.Timeout"],
                        "MaxAttempts": 1,
                        "IntervalSeconds": 1,
                        "BackoffRate": 1.0,
                    }
                ],
                "End": True,
            }
        },
    }
    sm_arn = _create_state_machine(ctx, definition, sfn_role_arn)
    exec_arn = _start_execution(ctx, sm_arn, {})
    desc = _wait_execution_terminal(ctx, exec_arn, timeout_s=90)

    assert desc["status"] == "FAILED", f"expected FAILED, got {desc['status']}"
    assert desc.get("error") == "States.Timeout", desc.get("error")

    # The Retry (MaxAttempts=1) must have re-invoked the function exactly once more:
    # initial attempt + 1 retry = 2 pings recorded on the queue.
    pings = _drain_queue(ctx, ping_queue["url"], min_count=2, timeout_s=30)
    assert len(pings) == 2, f"expected exactly 2 invocations (initial + 1 retry), got {len(pings)}"


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
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
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


def _retry_deadline(ctx, total_s=60.0):
    """Monotonic deadline for an IAM-propagation retry, capped by the check's remaining time."""
    deadline = time.monotonic() + total_s
    if ctx.time_left() is not None:
        deadline = min(deadline, time.monotonic() + ctx.time_left() - 5.0)
    return deadline


def _create_lambda_function(ctx, code, role_arn, timeout=30):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    zip_bytes = _zip_bytes(code)
    resp = None
    deadline = _retry_deadline(ctx)
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
                Tags={"sim2real:managed": "true"},
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] in ("InvalidParameterValueException", "AccessDeniedException") and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return resp["FunctionArn"]


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-sm-")
    arn = None
    deadline = _retry_deadline(ctx)
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real:managed", "value": "true"}],
            )["stateMachineArn"]
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise
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
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-q-"), tags={"sim2real:managed": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"url": url}


def _drain_queue(ctx, queue_url, min_count, timeout_s=30):
    sqs = ctx.client("sqs")
    bodies = []
    deadline = time.monotonic() + timeout_s
    while len(bodies) < min_count and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            bodies.append(m["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
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
