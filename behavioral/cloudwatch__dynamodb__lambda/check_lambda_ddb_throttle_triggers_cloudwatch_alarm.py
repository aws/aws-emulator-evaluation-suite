"""lambda-ddb-throttle-triggers-cloudwatch-alarm."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-ddb-throttle-triggers-cloudwatch-alarm"
GROUP = "alarm-state"
SERVICES = ["cloudwatch", "dynamodb", "lambda"]

_HANDLER_SRC = """
import os, boto3
from botocore.config import Config
from botocore.exceptions import ClientError

def handler(event, context):
    table = os.environ["TABLE_NAME"]
    ddb = boto3.client("dynamodb", config=Config(retries={"max_attempts": 0}))
    throttled = 0
    succeeded = 0
    for i in range(event.get("count", 80)):
        try:
            ddb.put_item(
                TableName=table,
                Item={"pk": {"S": "item-%d-%s" % (i, context.aws_request_id)}, "val": {"S": "x"}},
            )
            succeeded += 1
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ProvisionedThroughputExceededException":
                throttled += 1
            else:
                raise
    return {"throttled": throttled, "succeeded": succeeded}
"""


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx: Any) -> None:
    """Real DynamoDB throttling from a Lambda write burst raises ThrottledRequests and flips a CloudWatch alarm to ALARM."""
    table = _create_table(ctx, wcu=1, rcu=1)
    role_arn = _create_role(
        ctx,
        [{"Effect": "Allow", "Action": ["dynamodb:PutItem"], "Resource": "*"}],
    )
    fn = _create_function(ctx, role_arn, _HANDLER_SRC, env={"TABLE_NAME": table}, timeout=60)

    # The alarm exists before the burst, so the throttled minute is evaluated whichever second of
    # the minute the burst lands in, rather than possibly closing before the alarm is created.
    dims = [{"Name": "TableName", "Value": table}, {"Name": "Operation", "Value": "PutItem"}]
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-cwlambdadb-alarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace="AWS/DynamoDB",
        MetricName="ThrottledRequests",
        Dimensions=dims,
        Statistic="Sum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    total_throttled = 0
    for _ in range(3):
        resp = _invoke(ctx, fn, {"count": 80})
        total_throttled += resp["throttled"]
    assert total_throttled > 0, (
        f"expected at least one ProvisionedThroughputExceededException from the burst; "
        f"actual total_throttled={total_throttled}"
    )

    metric_wait_s = _budget(ctx, 300.0, 20.0)
    metric_sum = _poll_until(
        lambda: _metric_stat_sum(ctx, "AWS/DynamoDB", "ThrottledRequests", dims),
        lambda v: v > 0,
        timeout_s=metric_wait_s,
        interval_s=2,
    )
    if not metric_sum or metric_sum <= 0:
        raise AssertionError(
            f"ThrottledRequests datapoint did not appear within a {metric_wait_s:.0f}s poll "
            "window; "
            "CloudWatch metric ingestion for DynamoDB can take several minutes. "
            f"actual metric_sum={metric_sum!r}"
        )

    state = _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"],
        lambda s: s == "ALARM",
        timeout_s=_budget(ctx, 400.0),
        interval_s=2,
    )
    assert state == "ALARM", f"alarm never transitioned to ALARM (expected ALARM, actual last state={state!r})"

    history = cw.describe_alarm_history(AlarmName=alarm_name, HistoryItemType="StateUpdate")["AlarmHistoryItems"]
    assert any("ALARM" in item["HistorySummary"] for item in history), (
        f"expected an alarm-history StateUpdate item mentioning ALARM; "
        f"actual history summaries={[item['HistorySummary'] for item in history]!r}"
    )


_PREFIX = "sim2real-cwlambdadb-"
_LOGS_STMT = {
    "Effect": "Allow",
    "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
    "Resource": "*",
}


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _create_role(ctx: Any, statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    name = _xname(ctx, "role")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy_name = _xname(ctx, "policy")
    iam.put_role_policy(
        RoleName=name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [_LOGS_STMT, *statements]}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName=policy_name))
    return role["Role"]["Arn"]


def _zip_code(src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("handler.py", src)
    return buf.getvalue()


def _create_function(ctx: Any, role_arn: str, src: str, env: dict[str, str] | None = None, timeout: int = 30) -> str:
    lam = ctx.client("lambda")
    name = _xname(ctx, "fn")
    code = _zip_code(src)
    last_err = None
    for _ in range(12):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="handler.handler",
                Code={"ZipFile": code},
                Timeout=timeout,
                MemorySize=128,
                Environment={"Variables": env or {}},
                Tags={"sim2real": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(5)
    else:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return name


def _invoke(ctx: Any, function_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=function_name, Payload=json.dumps(payload).encode())
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation failed: {body}")
    return body


def _create_table(ctx: Any, wcu: int | None = None, rcu: int | None = None) -> str:
    ddb = ctx.client("dynamodb")
    name = _xname(ctx, "tbl")
    kwargs: dict[str, Any] = dict(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    if wcu is None:
        kwargs["BillingMode"] = "PAY_PER_REQUEST"
    else:
        kwargs["ProvisionedThroughput"] = {"ReadCapacityUnits": rcu, "WriteCapacityUnits": wcu}
    ddb.create_table(**kwargs)
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


def _budget(ctx: Any, cap_s: float, reserve_s: float = 5.0) -> float:
    """A wait's cap, cut to the runner's remaining time so the check fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - reserve_s))


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _metric_stat_sum(ctx: Any, namespace: str, metric_name: str, dimensions: list[dict[str, str]], stat: str = "Sum") -> float:
    cw = ctx.client("cloudwatch")
    now = datetime.now(timezone.utc)
    resp = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric_name,
        Dimensions=dimensions,
        StartTime=now - timedelta(minutes=15),
        EndTime=now + timedelta(minutes=1),
        Period=60,
        Statistics=[stat],
    )
    return sum(dp[stat] for dp in resp.get("Datapoints", []))


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
