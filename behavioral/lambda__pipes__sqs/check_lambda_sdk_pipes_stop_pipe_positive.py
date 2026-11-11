"""lambda-sdk-pipes-stop-pipe-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sdk-pipes-stop-pipe-positive"
GROUP = "arn-resolution"
SERVICES = ["lambda", "pipes", "sqs"]

_HANDLER_STOP = '''
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    pipes = boto3.client("pipes")
    try:
        resp = pipes.stop_pipe(Name=event["pipe_name"])
        return {"ok": True, "state": resp.get("CurrentState")}
    except ClientError as exc:
        return {"ok": False, "code": exc.response["Error"]["Code"]}
'''


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda handler calling pipes.stop_pipe() transitions a running pipe to STOPPED."""
    src_url, src_arn = _create_queue(ctx, "pipesrc")
    tgt_url, tgt_arn = _create_queue(ctx, "pipetgt")
    pipe_role_arn = _create_pipe_role(ctx, src_arn, tgt_arn)
    pipe_name, pipe_arn = _create_pipe(ctx, src_arn, tgt_arn, pipe_role_arn, "RUNNING")

    lambda_role_arn = _create_lambda_role(
        ctx, [{"Effect": "Allow", "Action": ["pipes:StopPipe"], "Resource": pipe_arn}]
    )
    func_name = _create_lambda_function(ctx, lambda_role_arn, _HANDLER_STOP)

    result = _invoke_lambda(ctx, func_name, {"pipe_name": pipe_name})
    assert result["ok"] is True, f"handler reported failure: {result}"
    assert result["state"] in ("STOPPING", "STOPPED"), f"unexpected CurrentState after stop_pipe: {result}"

    final_state = _wait_for_pipe_state(ctx, pipe_name, "STOPPED")
    assert final_state == "STOPPED", f"expected pipe to settle at STOPPED, got {final_state}"


def _create_queue(ctx, suffix: str):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name(f"sim2real-behav-{suffix}-"), tags={"env": "sim2real"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_pipe_role(ctx, source_arn, target_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-piperole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "pipes.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "env", "Value": "sim2real"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                "Resource": source_arn,
            },
            {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target_arn},
        ],
    }
    policy_name = "inline-policy"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_pipe(ctx, source_arn, target_arn, role_arn, desired_state):
    pipes = ctx.client("pipes")
    pipe_name = ctx.unique_name("sim2real-behav-pipe-")
    last_exc = None
    deadline = time.monotonic() + 90
    created = False
    while time.monotonic() < deadline:
        try:
            pipes.create_pipe(
                Name=pipe_name,
                RoleArn=role_arn,
                Source=source_arn,
                Target=target_arn,
                DesiredState=desired_state,
                Tags={"env": "sim2real"},
            )
            created = True
            break
        except pipes.exceptions.ValidationException as exc:
            last_exc = exc
            time.sleep(3)
    if not created:
        raise AssertionError(f"create_pipe never succeeded (role propagation?): {last_exc}")
    ctx.on_cleanup(lambda: _safe_delete_pipe(ctx, pipe_name))
    _wait_for_pipe_state(ctx, pipe_name, desired_state)
    pipe_arn = pipes.describe_pipe(Name=pipe_name)["Arn"]
    return pipe_name, pipe_arn


def _wait_for_pipe_state(ctx, pipe_name, expected_state, timeout_s=180.0, interval_s=5.0):
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = pipes.describe_pipe(Name=pipe_name)["CurrentState"]
        if state == expected_state:
            return state
        time.sleep(interval_s)
    raise AssertionError(f"pipe {pipe_name} never reached {expected_state}, last state={state}")


def _safe_delete_pipe(ctx, pipe_name):
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + 60
    while True:
        try:
            pipes.delete_pipe(Name=pipe_name)
            return
        except pipes.exceptions.NotFoundException:
            return
        except pipes.exceptions.ConflictException:
            if time.monotonic() >= deadline:
                raise
            time.sleep(5)


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
        Tags=[{"Key": "env", "Value": "sim2real"}],
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
            ctx.on_cleanup(lambda _n=func_name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=func_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Environment={"Variables": env or {}},
                Tags={"env": "sim2real"},
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
