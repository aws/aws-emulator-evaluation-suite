"""lambda-custom-logger-writes-to-cloudwatch."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "lambda-custom-logger-writes-to-cloudwatch"
GROUP = "log-delivery"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]

_BASIC_EXEC_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

_HANDLER_CODE = """
import os


def handler(event, context):
    print(os.environ["MARKER"])
    print(f"structured-log level=info marker={os.environ['MARKER']}")
    return {"ok": True}
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """Application-level print()/logger statements are delivered as CloudWatch log events."""
    marker = ctx.unique_name("sim2real-behav-marker-")
    role_arn = _create_lambda_role(ctx, managed_policy_arns=[_BASIC_EXEC_POLICY_ARN])
    name, _arn = _create_function(ctx, role_arn, _HANDLER_CODE, env={"MARKER": marker})
    log_group_name = f"/aws/lambda/{name}"
    _register_log_group_cleanup(ctx, log_group_name)

    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=name, Payload=json.dumps({}).encode("utf-8"))
    assert resp["StatusCode"] == 200, f"expected StatusCode 200, got {resp['StatusCode']}"
    assert "FunctionError" not in resp, f"invoke reported FunctionError: {resp.get('FunctionError')}"

    messages = _wait_for_log_messages(
        ctx,
        log_group_name,
        lambda msgs: any(marker in m for m in msgs),
        timeout_s=90.0,
    )
    plain_marker_lines = [m for m in messages if m.strip() == marker]
    structured_lines = [m for m in messages if f"marker={marker}" in m]
    assert plain_marker_lines, "bare print() marker line missing from CloudWatch Logs"
    assert structured_lines, "structured print() marker line missing from CloudWatch Logs"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_lambda_role(ctx, extra_statements=None, managed_policy_arns=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    for policy_arn in managed_policy_arns or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        ctx.on_cleanup(
            lambda p=policy_arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=p)
        )
    if extra_statements:
        policy_name = ctx.unique_name("sim2real-behav-policy-")
        doc = {"Version": "2012-10-17", "Statement": extra_statements}
        iam.put_role_policy(
            RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(doc)
        )
        ctx.on_cleanup(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        )
    return role_arn


def _create_function(
    ctx,
    role_arn,
    code,
    *,
    timeout=15,
    memory=128,
    env=None,
    logging_config=None,
    runtime="python3.12",
    handler="lambda_function.handler",
):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", code)
    kwargs = dict(
        FunctionName=name,
        Runtime=runtime,
        Role=role_arn,
        Handler=handler,
        Code={"ZipFile": buf.getvalue()},
        Timeout=timeout,
        MemorySize=memory,
        Publish=True,
        Tags={"sim2real:managed": "true"},
    )
    if env:
        kwargs["Environment"] = {"Variables": env}
    if logging_config:
        kwargs["LoggingConfig"] = logging_config
    last_err = None
    resp = None
    for _ in range(10):
        try:
            resp = lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(3)
    if resp is None:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_active(ctx, name)
    return name, resp["FunctionArn"]


def _wait_active(ctx, name, timeout_s=60.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"function {name} never became Active")


def _register_log_group_cleanup(ctx, log_group_name):
    logs = ctx.client("logs")

    def _cleanup():
        try:
            logs.delete_log_group(logGroupName=log_group_name)
        except logs.exceptions.ResourceNotFoundException:
            pass

    ctx.on_cleanup(_cleanup)


def _collect_log_messages(ctx, log_group_name):
    logs = ctx.client("logs")
    messages = []
    try:
        streams = logs.describe_log_streams(
            logGroupName=log_group_name, orderBy="LastEventTime", descending=True
        )["logStreams"]
    except logs.exceptions.ResourceNotFoundException:
        return messages
    for stream in streams:
        events = logs.get_log_events(
            logGroupName=log_group_name,
            logStreamName=stream["logStreamName"],
            startFromHead=True,
        )["events"]
        messages.extend(e["message"] for e in events)
    return messages


def _wait_for_log_messages(ctx, log_group_name, predicate, timeout_s=90.0, interval_s=3.0):
    return _poll_until(
        lambda: _collect_log_messages(ctx, log_group_name),
        predicate,
        timeout_s=timeout_s,
        interval_s=interval_s,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
