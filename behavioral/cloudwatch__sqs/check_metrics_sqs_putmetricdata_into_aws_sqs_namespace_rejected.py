"""metrics-sqs-putmetricdata-into-aws-sqs-namespace-rejected."""

# On real AWS:
# PutMetricData(Namespace="AWS/SQS", ...) returned HTTP 400, Error.Code "InvalidParameterValue",
# Message "The value AWS/ for parameter Namespace is invalid.".

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metrics-sqs-putmetricdata-into-aws-sqs-namespace-rejected"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "sqs"]

_NS = "AWS/SQS"
_VIS = "ApproximateNumberOfMessagesVisible"
#: A value no queue in this check can reach, so its appearance anywhere is unambiguous.
_SPOOF = 987654.0
_N_SENT = 2
_ARRIVAL_BUDGET_S = 900.0
_REFUSAL_MESSAGE = "The value AWS/ for parameter Namespace is invalid."


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-available-cloudwatch-metrics.html
@tags(
    "axis:rejection",
    "cap:c2",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """PutMetricData into Namespace=AWS/SQS for a real queue is refused with 400 InvalidParameterValue
    and the genuine series reads only the 2 messages actually sent, while the same put into a custom
    namespace reads back: a customer must not overwrite the series autoscaling scales on."""
    sqs = ctx.client("sqs")
    cw = ctx.client("cloudwatch")

    name = ctx.unique_name("sim2real-cwsqs-spoof-")
    url = sqs.create_queue(
        QueueName=name, tags={"sim2real": "cloudwatch__sqs", "sim2real-check": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    start = datetime.now(timezone.utc) - timedelta(minutes=10)
    for i in range(_N_SENT):
        sqs.send_message(QueueUrl=url, MessageBody=f"spoof-body-{i}")

    datum = {
        "MetricName": _VIS,
        "Dimensions": [{"Name": "QueueName", "Value": name}],
        "Value": _SPOOF,
        "Unit": "Count",
    }

    # ---- the refusal ---------------------------------------------------------------------------- #
    code, status, message = _error(lambda: cw.put_metric_data(Namespace=_NS, MetricData=[datum]))
    assert (code, status) == ("InvalidParameterValue", 400), (
        f"PutMetricData into the service-owned namespace {_NS!r} returned "
        f"code={code!r} status={status!r}; real AWS refuses it with InvalidParameterValue/400"
    )
    assert message == _REFUSAL_MESSAGE, (
        f"PutMetricData into {_NS!r} was refused with message {message!r}; real AWS says "
        f"{_REFUSAL_MESSAGE!r}"
    )

    # ---- positive control: the write path itself works, outside AWS/ ------------------------ #
    custom_ns = ctx.unique_name("Sim2Real/cwsqs-")
    cw.put_metric_data(Namespace=custom_ns, MetricData=[datum])
    custom = _poll(
        lambda: _points(cw, custom_ns, name, start),
        lambda p: bool(p),
        description=f"the control datum in custom namespace {custom_ns!r} reading back",
    )
    assert custom == [_SPOOF], (
        f"the same datum put into {custom_ns!r} read back as {custom!r}, expected [{_SPOOF}]"
    )

    # ---- effect absent: the genuine series carries the real depth, never the spoof ------------ #
    real = _poll(
        lambda: _points(cw, _NS, name, start),
        lambda p: float(_N_SENT) in p,
        description=f"AWS/SQS {_VIS} for QueueName={name} reaching {_N_SENT}",
    )
    assert _SPOOF not in real, (
        f"the refused value {_SPOOF} appears in the service-owned series AWS/SQS {_VIS} "
        f"QueueName={name}: {real!r}"
    )
    assert max(real) == float(_N_SENT), (
        f"AWS/SQS {_VIS} for QueueName={name} peaked at {max(real)!r}; exactly {_N_SENT} messages "
        f"were sent and none received, so no datapoint may exceed {_N_SENT} ({real!r})"
    )


# ===== helpers =====
def _error(fn) -> tuple[str, int, str]:
    """(Error.Code, HTTP status, Error.Message) of the call. An unexpected SUCCESS raises: the spoofed datum was
    accepted, which is the strongest failure this check exists to catch."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return (
            exc.response["Error"]["Code"],
            exc.response["ResponseMetadata"]["HTTPStatusCode"],
            exc.response["Error"].get("Message"),
        )
    raise AssertionError(
        f"PutMetricData into {_NS!r} SUCCEEDED; a customer write into a service-owned AWS/ "
        f"namespace must be refused"
    )


def _points(cw, namespace: str, queue: str, start: datetime) -> list[float]:
    dps = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=_VIS,
        Dimensions=[{"Name": "QueueName", "Value": queue}],
        StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=5),
        Period=60,
        Statistics=["Maximum"],
    )["Datapoints"]
    return [float(d["Maximum"]) for d in sorted(dps, key=lambda d: d["Timestamp"])]


def _poll(probe, ok, *, timeout_s=_ARRIVAL_BUDGET_S, interval_s=20.0, description="value"):
    deadline = time.monotonic() + timeout_s
    while True:
        got = probe()
        if ok(got):
            return got
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} never arrived within {timeout_s}s; last {got!r}")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
