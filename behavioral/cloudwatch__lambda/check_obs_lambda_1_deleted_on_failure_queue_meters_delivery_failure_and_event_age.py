"""obs-lambda-1-deleted-on-failure-queue-meters-delivery-failure-and-event-age."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "obs-lambda-1-deleted-on-failure-queue-meters-delivery-failure-and-event-age"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "lambda"]

_RETRIES = 1
_ATTEMPTS = _RETRIES + 1
# Lambda waits about a minute before the first retry, with jitter; half of that leaves a margin
# while still failing a target that retries immediately.
_RETRY_AGE_FLOOR_MS = 30_000
_DELIVERY_BUDGET_S = 300.0
_METRIC_BUDGET_S = 300.0
_ROLE_PROPAGATION_BUDGET_S = 120.0

_HANDLER = '''
def handler(event, context):
    raise RuntimeError("sim2real deliberate failure")
'''


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics-types.html
@tags(
    "cap:c3", "cap:c4", "concern:metrics", "concern:eventing", "concern:negative-classes", "concern:data-plane",
    "dp:api", "plane:data", "axis:happy-path",
    "timing:real-time",
)
def run(ctx) -> None:
    """An async event whose OnFailure queue was deleted is metered once as
    DestinationDeliveryFailures, while a twin with a live queue receives its RetriesExhausted
    record and meters none; on both, AsyncEventAge reflects the retry backoff.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics-types.html
    """
    from botocore.exceptions import ClientError

    start = datetime.now(timezone.utc).replace(second=0, microsecond=0) - timedelta(minutes=1)
    lam = ctx.client("lambda")
    cw = ctx.client("cloudwatch")
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")

    live_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-olam-dlive-")[:80],
        tags={"sim2real": "cloudwatch__lambda"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=live_url))
    gone_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-olam-dgone-")[:80],
        tags={"sim2real": "cloudwatch__lambda"},
    )["QueueUrl"]
    # run() deletes this queue itself; the teardown covers a failure before that point.
    ctx.on_cleanup(lambda: _delete_queue_if_present(sqs, gone_url))
    live_arn = _queue_arn(sqs, live_url)
    gone_arn = _queue_arn(sqs, gone_url)

    role_arn = _role(ctx)
    role_name = role_arn.rsplit("/", 1)[1]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-olam-dest",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "sqs:SendMessage",
                        "Resource": [live_arn, gone_arn],
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-olam-dest")
    )

    good = _function(ctx, lam, role_arn, "dlive")
    bad = _function(ctx, lam, role_arn, "dgone")
    for fn, dest in ((good, live_arn), (bad, gone_arn)):
        _configure(ctx, lam, fn, dest)

    # The only difference between the two functions: the subject's destination queue is deleted.
    sqs.delete_queue(QueueUrl=gone_url)

    def _gone_code():
        try:
            sqs.get_queue_attributes(QueueUrl=gone_url, AttributeNames=["QueueArn"])
            return None
        except ClientError as exc:
            return exc.response["Error"]["Code"]

    _poll_until(
        _gone_code,
        lambda code: code == "AWS.SimpleQueueService.NonExistentQueue",
        timeout_s=90.0,
        interval_s=3.0,
        description=f"GetQueueAttributes on the deleted queue {gone_url} reporting NonExistentQueue",
    )

    payload = {"sim2real": "obs-lambda-1", "seq": 1}
    t_invoke = time.time()
    for fn in (good, bad):
        r = lam.invoke(FunctionName=fn, InvocationType="Event", Payload=json.dumps(payload).encode())
        assert r["StatusCode"] == 202, f"async invoke of {fn} returned {r['StatusCode']!r}"

    # Positive control: the twin's failure record reaches the live queue.
    records = []
    deadline = time.monotonic() + _DELIVERY_BUDGET_S
    while not records and time.monotonic() < deadline:
        for m in sqs.receive_message(
            QueueUrl=live_url, MaxNumberOfMessages=10, WaitTimeSeconds=10
        ).get("Messages", []):
            records.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=live_url, ReceiptHandle=m["ReceiptHandle"])
    t_record = time.time()
    assert len(records) == 1, (
        f"the live destination received {len(records)} records within {_DELIVERY_BUDGET_S}s, "
        f"expected 1: {records!r}"
    )
    rec = records[0]
    rc = rec.get("requestContext", {})
    assert rc.get("condition") == "RetriesExhausted", f"record condition {rc.get('condition')!r}"
    assert rc.get("approximateInvokeCount") == _ATTEMPTS, (
        f"record approximateInvokeCount {rc.get('approximateInvokeCount')!r}, expected {_ATTEMPTS}"
    )
    assert rec.get("requestPayload") == payload, f"record payload {rec.get('requestPayload')!r}"
    assert rc.get("functionArn", "").split(":")[6] == good, f"record functionArn {rc!r}"

    good_dims = [("FunctionName", good)]
    bad_dims = [("FunctionName", bad)]
    queries = {
        "bddf": ("DestinationDeliveryFailures", bad_dims, "Sum"),
        "binv": ("Invocations", bad_dims, "Sum"),
        "berr": ("Errors", bad_dims, "Sum"),
        "brcv": ("AsyncEventsReceived", bad_dims, "Sum"),
        "bage": ("AsyncEventAge", bad_dims, "Maximum"),
        "gddf": ("DestinationDeliveryFailures", good_dims, "Sum"),
        "ginv": ("Invocations", good_dims, "Sum"),
        "gage": ("AsyncEventAge", good_dims, "Maximum"),
    }
    seen = _poll_until(
        lambda: _read(cw, queries, start),
        lambda got: sum(got["bddf"]) >= 1
        and sum(got["binv"]) >= _ATTEMPTS
        and sum(got["berr"]) >= _ATTEMPTS
        and sum(got["brcv"]) >= 1
        and sum(got["ginv"]) >= _ATTEMPTS
        and max(got["bage"], default=0) >= _RETRY_AGE_FLOOR_MS
        and max(got["gage"], default=0) >= _RETRY_AGE_FLOOR_MS,
        timeout_s=_METRIC_BUDGET_S,
        interval_s=15.0,
        description="the subject's DestinationDeliveryFailures and both retry ages",
    )
    observed_ms = (time.time() - t_invoke) * 1000.0

    assert sum(seen["bddf"]) == 1.0, (
        f"DestinationDeliveryFailures Sum for {bad} (OnFailure queue deleted) is "
        f"{sum(seen['bddf'])!r}, expected exactly 1 for one event; read {seen!r}"
    )
    assert sum(seen["binv"]) == float(_ATTEMPTS) and sum(seen["berr"]) == float(_ATTEMPTS), (
        f"{bad} Invocations {sum(seen['binv'])!r} / Errors {sum(seen['berr'])!r}, expected "
        f"{_ATTEMPTS} each (MaximumRetryAttempts={_RETRIES})"
    )
    assert sum(seen["brcv"]) == 1.0, (
        f"AsyncEventsReceived Sum for {bad} is {sum(seen['brcv'])!r}, expected 1"
    )
    assert sum(seen["gddf"]) == 0.0, (
        f"the live-queue twin {good} delivered its record yet shows "
        f"DestinationDeliveryFailures {seen['gddf']!r}"
    )
    # The twin's retry happened before its record was delivered, so its age is bounded by that
    # arrival; the subject's by the moment the metrics were read.
    record_ms = (t_record - t_invoke) * 1000.0
    for label, key, ceiling in (("subject", "bage", observed_ms), ("twin", "gage", record_ms)):
        age = max(seen[key])
        assert _RETRY_AGE_FLOOR_MS <= age <= ceiling, (
            f"{label} AsyncEventAge Maximum is {age!r} ms, expected in "
            f"[{_RETRY_AGE_FLOOR_MS}, {ceiling:.0f}] (retry-backoff floor .. wall clock from the "
            f"invoke); values {seen[key]!r}"
        )


def _configure(ctx, lam, fn: str, dest_arn: str) -> None:
    """PutFunctionEventInvokeConfig validates the role's access to the destination, so absorb
    the inline policy's IAM propagation with a bounded retry at that first use."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + _ROLE_PROPAGATION_BUDGET_S
    while True:
        try:
            lam.put_function_event_invoke_config(
                FunctionName=fn,
                MaximumRetryAttempts=_RETRIES,
                DestinationConfig={"OnFailure": {"Destination": dest_arn}},
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"PutFunctionEventInvokeConfig {fn} -> {dest_arn} kept refusing for "
                    f"{_ROLE_PROPAGATION_BUDGET_S}s: {exc!r}"
                ) from exc
            time.sleep(5.0)
    ctx.on_cleanup(lambda: lam.delete_function_event_invoke_config(FunctionName=fn))
    got = lam.get_function_event_invoke_config(FunctionName=fn)
    assert got["DestinationConfig"]["OnFailure"]["Destination"] == dest_arn, (
        f"{fn} OnFailure read back {got['DestinationConfig']!r}, set {dest_arn}"
    )


def _delete_queue_if_present(sqs, url: str) -> None:
    from botocore.exceptions import ClientError

    try:
        sqs.delete_queue(QueueUrl=url)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code not in ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"):
            raise


def _queue_arn(sqs, url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]


def _read(cw, queries: dict, start: datetime) -> dict:
    """GetMetricData over [start, now+2m) at 60 s; returns id -> list of datapoint values."""
    q = [
        {
            "Id": qid,
            "MetricStat": {
                "Metric": {
                    "Namespace": "AWS/Lambda",
                    "MetricName": metric,
                    "Dimensions": [{"Name": k, "Value": v} for k, v in dims],
                },
                "Period": 60,
                "Stat": stat,
            },
            "ReturnData": True,
        }
        for qid, (metric, dims, stat) in queries.items()
    ]
    out: dict = {qid: [] for qid in queries}
    kwargs = {
        "MetricDataQueries": q,
        "StartTime": start,
        "EndTime": datetime.now(timezone.utc) + timedelta(minutes=2),
    }
    while True:
        resp = cw.get_metric_data(**kwargs)
        for r in resp["MetricDataResults"]:
            out[r["Id"]].extend(float(v) for v in r["Values"])
        if not resp.get("NextToken"):
            return out
        kwargs["NextToken"] = resp["NextToken"]


def _zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, src in files.items():
            zf.writestr(path, src)
    return buf.getvalue()


def _role(ctx) -> str:
    """An execution role with NO CloudWatch Logs permission, on purpose: the metrics under test
    are published by the Lambda service, and a role that cannot create a log group leaves no
    /aws/lambda/<fn> group behind."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-olam-role-")[:64]
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

    name = ctx.unique_name(f"sim2real-olam-{label}-")[:64]
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


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} did not happen within {timeout_s}s; last read {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
