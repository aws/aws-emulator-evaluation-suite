"""metrics-lambda-dead-letter-errors-counted-only-when-dlq-delivery-fails."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metrics-lambda-dead-letter-errors-counted-only-when-dlq-delivery-fails"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "lambda"]

_EVENTS = 2
_METRIC_BUDGET_S = 240.0
_ABSENCE_HOLD_S = 30.0
_ROLE_PROPAGATION_BUDGET_S = 120.0

_HANDLER = '''
import time


def handler(event, context):
    time.sleep(event.get("sleep_ms", 0) / 1000.0)
    if event.get("fail"):
        raise RuntimeError("sim2real deliberate failure")
    return {"ok": True}
'''


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics.html
@tags(
    "cap:c3",
    "concern:metrics",
    "concern:eventing",
    "concern:data-plane",
    "dp:api",
    "plane:data",
    "axis:happy-path",
    "timing:real-time",
)
def run(ctx) -> None:
    """Of two always-failing async functions, the one whose DLQ is a live queue delivers both events
    there and publishes no DeadLetterErrors, the one whose SNS DLQ was deleted meters
    DeadLetterErrors=2 (Unit Count); both meter Errors and AsyncEventsDropped 2."""
    start = datetime.now(timezone.utc) - timedelta(minutes=2)
    lam = ctx.client("lambda")
    cw = ctx.client("cloudwatch")
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    iam = ctx.client("iam")

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-mlam-dlq-")[:80],
        tags={"sim2real": "cloudwatch__lambda"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-mlam-dlt-")[:256],
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__lambda"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    role_arn = _role(ctx)
    role_name = role_arn.rsplit("/", 1)[1]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-mlam-dlq",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn},
                    {"Effect": "Allow", "Action": "sns:Publish", "Resource": topic_arn},
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-mlam-dlq")
    )

    # CreateFunction test-delivers to the DLQ, so both targets must be live and permitted here;
    # the _function retry absorbs the policy's propagation delay.
    good = _function(ctx, lam, role_arn, "dlq", DeadLetterConfig={"TargetArn": queue_arn})
    bad = _function(ctx, lam, role_arn, "dlt", DeadLetterConfig={"TargetArn": topic_arn})
    for fn in (good, bad):
        lam.put_function_event_invoke_config(FunctionName=fn, MaximumRetryAttempts=0)

    # Break exactly one thing: the bad function's dead-letter target stops existing.
    sns.delete_topic(TopicArn=topic_arn)
    _poll_until(
        lambda: _topic_code(sns, topic_arn),
        lambda code: code == "NotFound",
        timeout_s=60.0,
        interval_s=3.0,
        description=f"GetTopicAttributes on the deleted topic {topic_arn} returning NotFound",
    )

    payloads = [{"fail": True, "seq": i} for i in range(_EVENTS)]
    for fn in (good, bad):
        for p in payloads:
            r = lam.invoke(FunctionName=fn, InvocationType="Event", Payload=json.dumps(p).encode())
            assert r["StatusCode"] == 202, f"async invoke of {fn} returned {r['StatusCode']!r}"

    # The live DLQ receives both events, with their original bodies.
    bodies: list[dict] = []
    deadline = time.monotonic() + _METRIC_BUDGET_S
    while len(bodies) < _EVENTS and time.monotonic() < deadline:
        for m in sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10,
            MessageAttributeNames=["All"],
        ).get("Messages", []):
            attrs = m.get("MessageAttributes", {})
            assert "RequestID" in attrs and "ErrorMessage" in attrs, (
                f"DLQ message lacks Lambda's RequestID/ErrorMessage attributes: {sorted(attrs)!r}"
            )
            bodies.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    assert sorted(bodies, key=lambda b: b["seq"]) == payloads, (
        f"the live DLQ received {bodies!r}, expected exactly the {_EVENTS} events {payloads!r}"
    )

    want = {
        ("DeadLetterErrors", bad): _EVENTS,
        ("Errors", bad): _EVENTS,
        ("AsyncEventsDropped", bad): _EVENTS,
        ("Errors", good): _EVENTS,
        ("AsyncEventsDropped", good): _EVENTS,
    }
    seen = _poll_until(
        lambda: {k: _sum(cw, k[0], [("FunctionName", k[1])], start) for k in want},
        lambda got: all(got[k] is not None and got[k] >= v for k, v in want.items()),
        timeout_s=_METRIC_BUDGET_S,
        interval_s=15.0,
        description=f"DLQ accounting reaching {want!r}",
    )
    for (metric, fn), expected in want.items():
        label = "deleted-topic DLQ" if fn == bad else "live-queue DLQ"
        assert seen[(metric, fn)] == float(expected), (
            f"AWS/Lambda {metric} Sum for the {label} function {fn} is {seen[(metric, fn)]!r}, "
            f"expected exactly {float(expected)!r} (all read: {seen!r})"
        )
    units = {d["Unit"] for d in _series(cw, "DeadLetterErrors", [("FunctionName", bad)], start, ["Sum"])}
    assert units == {"Count"}, f"DeadLetterErrors Unit(s) {units!r}"

    # Effect absent: every hand-off to the live queue succeeded, so no DeadLetterErrors series.
    _assert_stays(
        lambda: _sum(cw, "DeadLetterErrors", [("FunctionName", good)], start),
        None,
        hold_s=_ABSENCE_HOLD_S,
        description=f"DeadLetterErrors for {good}, whose DLQ received every event",
    )
    final = _sum(cw, "DeadLetterErrors", [("FunctionName", bad)], start)
    assert final == float(_EVENTS), f"DeadLetterErrors for {bad} re-read as {final!r}"


def _topic_code(sns, topic_arn: str) -> str:
    from botocore.exceptions import ClientError

    try:
        sns.get_topic_attributes(TopicArn=topic_arn)
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return "EXISTS"


def _zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, src in files.items():
            zf.writestr(path, src)
    return buf.getvalue()


def _role(ctx) -> str:
    """An execution role with NO CloudWatch Logs permission, on purpose: the metrics under test are
    published by the Lambda service, not by the function, and a role that cannot create a log
    group means the check leaves no /aws/lambda/<fn> group behind."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-mlam-role-")[:64]
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=[{"Key": "sim2real", "Value": "cloudwatch__lambda"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _function(ctx, lam, role_arn: str, label: str, **extra) -> str:
    from botocore.exceptions import ClientError

    name = ctx.unique_name(f"sim2real-mlam-{label}-")[:64]
    logs = ctx.client("logs")
    # Registered BEFORE the create so LIFO runs it AFTER delete_function.
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{name}"))
    deadline = time.monotonic() + _ROLE_PROPAGATION_BUDGET_S
    while True:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="handler.handler",
                Code={"ZipFile": _zip({"handler.py": _HANDLER})},
                Timeout=15,
                MemorySize=128,
                Tags={"sim2real": "cloudwatch__lambda"},
                **extra,
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"CreateFunction {name} kept refusing the fresh role for "
                    f"{_ROLE_PROPAGATION_BUDGET_S}s: {exc!r}"
                ) from exc
            time.sleep(5.0)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(
        FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 60}
    )
    return name


def _reap_log_group(logs, group: str) -> None:
    """delete_function leaves the log group, and a late flush can recreate it — so delete in a
    bounded loop until a quiet read confirms it is gone."""
    from botocore.exceptions import ClientError

    for _ in range(4):
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(5.0)
        found = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
        if not any(g["logGroupName"] == group for g in found):
            return
    raise AssertionError(f"log group {group} kept reappearing after deletion")


def _series(cw, metric: str, dims: list[tuple[str, str]], start, stats: list[str]) -> list[dict]:
    return cw.get_metric_statistics(
        Namespace="AWS/Lambda",
        MetricName=metric,
        Dimensions=[{"Name": k, "Value": v} for k, v in dims],
        StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=2),
        Period=60,
        Statistics=stats,
    )["Datapoints"]


def _sum(cw, metric: str, dims: list[tuple[str, str]], start) -> float | None:
    dps = _series(cw, metric, dims, start, ["Sum"])
    return float(sum(d["Sum"] for d in dps)) if dps else None


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} did not happen within {timeout_s}s; last read {last!r}")


def _assert_stays(probe, expected, *, hold_s, interval_s=10.0, description="reading"):
    deadline = time.monotonic() + hold_s
    while True:
        got = probe()
        assert got == expected, (
            f"{description}: read {got!r}, expected it to stay {expected!r} for {hold_s}s"
        )
        if time.monotonic() >= deadline:
            return
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
