"""cloudwatch-alarm-on-lambda-error-rate-transitions-alarm."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cloudwatch-alarm-on-lambda-error-rate-transitions-alarm"
GROUP = "alarm-state"
SERVICES = ["cloudwatch", "dynamodb", "lambda"]

_HANDLER_SRC = '''
def handler(event, context):
    raise RuntimeError("boom")
'''


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A CloudWatch alarm on a Lambda function's Errors metric transitions to ALARM after repeated failures."""
    role_arn = _create_lambda_role(
        ctx, policy_arns=["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"]
    )
    name = _create_function(ctx, role_arn, _HANDLER_SRC)

    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-cwlam-alarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace="AWS/Lambda",
        MetricName="Errors",
        Dimensions=[{"Name": "FunctionName", "Value": name}],
        Statistic="Sum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1,
        ComparisonOperator="GreaterThanOrEqualToThreshold",
        TreatMissingData="notBreaching",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    lam = ctx.client("lambda")
    for _ in range(3):
        resp = lam.invoke(FunctionName=name, Payload=b"{}")
        assert resp.get("FunctionError") == "Unhandled", (
            f"expected each invoke to report FunctionError=Unhandled, got {resp.get('FunctionError')!r}"
        )

    def probe():
        return cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"]

    final_state = _poll_until(ctx, probe, lambda s: s == "ALARM", timeout_s=360.0, interval_s=2.0)
    if final_state != "ALARM":
        raise AssertionError(
            "alarm never transitioned to ALARM within 6 minutes; CloudWatch metric ingestion plus "
            "alarm evaluation for AWS/Lambda Errors has multi-minute end-to-end latency on real AWS"
        )
    history = cw.describe_alarm_history(AlarmName=alarm_name, HistoryItemType="StateUpdate")["AlarmHistoryItems"]

    def _new_state(item):
        try:
            return json.loads(item["HistoryData"])["newState"]["stateValue"]
        except (KeyError, ValueError, TypeError):
            return None

    assert any(_new_state(item) == "ALARM" for item in history), (
        f"expected an ALARM state-update entry in alarm history, "
        f"got new states={[_new_state(h) for h in history]}"
    )


def _poll_until(ctx, probe, predicate, timeout_s=60.0, interval_s=2.0):
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _zip_bytes(filename: str, source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, source)
    return buf.getvalue()


def _create_lambda_role(ctx, policy_arns=None, inline_policies=None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cwlam-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    for arn in policy_arns or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
        ctx.on_cleanup(lambda a=arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=a))
    for i, doc in enumerate(inline_policies or []):
        pname = f"inline-{i}"
        iam.put_role_policy(RoleName=role_name, PolicyName=pname, PolicyDocument=json.dumps(doc))
        ctx.on_cleanup(lambda p=pname: iam.delete_role_policy(RoleName=role_name, PolicyName=p))
    return role_arn


def _create_function(
    ctx,
    role_arn: str,
    code_source: str,
    handler: str = "lambda_function.handler",
    timeout: int = 30,
    memory: int = 128,
    env: dict[str, str] | None = None,
    reserved_concurrency: int | None = None,
) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-cwlam-fn-")
    code_bytes = _zip_bytes("lambda_function.py", code_source)
    kwargs: dict[str, Any] = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler=handler,
        Code={"ZipFile": code_bytes},
        Timeout=timeout,
        MemorySize=memory,
        Publish=True,
        Tags={"sim2real:managed": "true"},
    )
    if env:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + 60.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException as err:
            last_err = err
            time.sleep(2.0)
    else:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    if reserved_concurrency is not None:
        lam.put_function_concurrency(FunctionName=name, ReservedConcurrentExecutions=reserved_concurrency)
    return name


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
