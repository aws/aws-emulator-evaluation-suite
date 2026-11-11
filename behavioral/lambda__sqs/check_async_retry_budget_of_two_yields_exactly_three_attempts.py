"""async-retry-budget-of-two-yields-exactly-three-attempts."""

# AWS behaviors this check relies on:
#   H1  MaximumRetryAttempts=2 produces exactly THREE handler entries for one asynchronous
#       invocation (the original plus two retries), and the OnFailure record reports
#       requestContext.approximateInvokeCount == 3.
#   H2  Lambda's asynchronous retry backoff (documented as roughly 1 minute then 2 minutes) means
#       the exhausted record can take ~5 minutes to arrive. _TOTAL_BUDGET_S is set to 900 s.
#   H3  Retries reuse the same event, so every attempt's counting message carries the same marker;
#       distinct aws_request_id values per attempt are NOT assumed either way — the check records
#       what it sees.
#   H4  The OnFailure destination is written with the FUNCTION's execution role, so sqs:SendMessage
#       on the destination queue must be granted to that role (as it is here).
#   H5  requestContext.condition == "RetriesExhausted" for both the 0-retry and the 2-retry
#       function.
#   H6  A calibrated quiet window equal to the observed span between the first and last attempt is
#       long enough to catch a fourth attempt if the target has one.

from __future__ import annotations

import collections
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "async-retry-budget-of-two-yields-exactly-three-attempts"
GROUP = "event-propagation"
SERVICES = ["lambda", "sqs"]

_TOTAL_BUDGET_S = 900.0
_MIN_QUIET_S = 90.0

# The `boto3.client` below is inside the DEPLOYED payload: it runs in the target's own Lambda
# runtime against the target's own ambient endpoint, not in the check process, so it does not use
# ctx.client.
_HANDLER = """\
import json
import os

import boto3

_SQS = boto3.client("sqs")
_COUNT_QUEUE = os.environ["COUNT_QUEUE_URL"]


def handler(event, context):
    _SQS.send_message(
        QueueUrl=_COUNT_QUEUE,
        MessageBody=json.dumps({
            "marker": event["marker"],
            "request_id": context.aws_request_id,
            "log_stream": context.log_stream_name,
        }),
    )
    raise RuntimeError("deliberate failure for " + event["marker"])
"""


# timing:real-time — schedule: 180 s https://docs.aws.amazon.com/lambda/latest/dg/invocation-async-error-handling.html
@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data", "timing:real-time",
)
def run(ctx) -> None:
    """MaximumRetryAttempts=2 yields exactly three handler entries counted on an independent queue,
    while a 0-retry twin on the same wiring yields exactly one, and neither exceeds its budget over a
    quiet window: the count comes from an SQS side channel because the API reports only the failure.
    """
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")

    count_url, count_arn = _create_queue(ctx, sqs, "count-")
    dest_two_url, dest_two_arn = _create_queue(ctx, sqs, "dest-two-")
    dest_zero_url, dest_zero_arn = _create_queue(ctx, sqs, "dest-zero-")

    role_arn = _create_execution_role(ctx, iam, [count_arn, dest_two_arn, dest_zero_arn])

    fn_two = _deploy(ctx, lam, role_arn, count_url, "retry2")
    fn_zero = _deploy(ctx, lam, role_arn, count_url, "retry0")
    _set_retry_budget(ctx, lam, fn_two, 2, dest_two_arn)
    _set_retry_budget(ctx, lam, fn_zero, 0, dest_zero_arn)

    marker_two = ctx.unique_name("marker-two-")
    marker_zero = ctx.unique_name("marker-zero-")
    _invoke_async(lam, fn_two, marker_two)
    _invoke_async(lam, fn_zero, marker_zero)

    attempts, records = _pump(
        sqs,
        count_url,
        {"two": dest_two_url, "zero": dest_zero_url},
        timeout_s=_TOTAL_BUDGET_S,
    )

    # ---- the twin control: a 0-retry budget spends exactly one attempt ----
    zero_attempts = attempts.get(marker_zero, [])
    assert len(zero_attempts) == 1, (
        f"MaximumRetryAttempts=0 must produce exactly ONE handler entry; the counting queue "
        f"received {len(zero_attempts)} messages for {marker_zero!r}: "
        f"{[a['request_id'] for a in zero_attempts]}"
    )
    zero_ctx = records["zero"].get("requestContext", {})
    assert zero_ctx.get("condition") == "RetriesExhausted", (
        f"the 0-retry failure record must report condition=RetriesExhausted, got "
        f"{zero_ctx.get('condition')!r} (record {records['zero']!r})"
    )
    assert zero_ctx.get("approximateInvokeCount") == 1, (
        f"MaximumRetryAttempts=0 must report approximateInvokeCount 1, got "
        f"{zero_ctx.get('approximateInvokeCount')!r}"
    )

    # ---- the subject: a 2-retry budget spends exactly three ----
    two_attempts = attempts.get(marker_two, [])
    assert len(two_attempts) == 3, (
        f"MaximumRetryAttempts=2 must produce exactly THREE handler entries (the original plus two "
        f"retries); the counting queue received {len(two_attempts)} for {marker_two!r}: "
        f"{[a['request_id'] for a in two_attempts]}"
    )
    two_ctx = records["two"].get("requestContext", {})
    assert two_ctx.get("condition") == "RetriesExhausted", (
        f"the 2-retry failure record must report condition=RetriesExhausted, got "
        f"{two_ctx.get('condition')!r} (record {records['two']!r})"
    )
    assert two_ctx.get("approximateInvokeCount") == 3, (
        f"MaximumRetryAttempts=2 must report approximateInvokeCount 3 — matching the "
        f"{len(two_attempts)} attempts counted on the side channel — got "
        f"{two_ctx.get('approximateInvokeCount')!r}"
    )
    assert records["two"].get("requestPayload") == {"marker": marker_two}, (
        f"the failure record must carry the original event unchanged, got "
        f"{records['two'].get('requestPayload')!r}"
    )
    assert two_attempts[0]["marker"] == marker_two, (
        f"every retry must replay the SAME event; the first attempt saw "
        f"{two_attempts[0]['marker']!r}"
    )

    # ---- the budget is a ceiling: a quiet window calibrated on the observed retry span ----
    span_s = two_attempts[-1]["seen_at"] - two_attempts[0]["seen_at"]
    quiet_s = max(span_s, _MIN_QUIET_S)
    extra = _drain_for(sqs, count_url, quiet_s)
    late_two = [m for m in extra if m["marker"] == marker_two]
    late_zero = [m for m in extra if m["marker"] == marker_zero]
    assert late_two == [], (
        f"a 2-retry budget was already spent in {len(two_attempts)} attempts, yet {len(late_two)} "
        f"more arrived over the following {quiet_s:.0f}s (the span the three attempts themselves "
        f"took was {span_s:.0f}s), so the budget is not a ceiling"
    )
    assert late_zero == [], (
        f"a 0-retry budget produced {len(late_zero)} further attempts over {quiet_s:.0f}s"
    )


# ===== helpers =====

def _make_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _create_queue(ctx, sqs, label: str) -> tuple[str, str]:
    name = ctx.unique_name(f"sim2real-behav-retry-{label}")
    created = sqs.create_queue(QueueName=name, tags={"sim2real": CHECK})
    url = created["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return url, arn


def _deploy(ctx, lam, role_arn: str, count_url: str, label: str) -> str:
    fn = ctx.unique_name(f"sim2real-behav-{label}-")
    _create_function(
        ctx,
        lam,
        FunctionName=fn,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _make_zip({"index.py": _HANDLER})},
        Environment={"Variables": {"COUNT_QUEUE_URL": count_url}},
        MemorySize=256,
        Timeout=30,
        Tags={"sim2real": CHECK},
    )
    _wait_active(lam, fn)
    return fn


def _set_retry_budget(ctx, lam, fn: str, attempts: int, destination_arn: str) -> None:
    lam.put_function_event_invoke_config(
        FunctionName=fn,
        MaximumRetryAttempts=attempts,
        DestinationConfig={"OnFailure": {"Destination": destination_arn}},
    )
    ctx.on_cleanup(lambda: lam.delete_function_event_invoke_config(FunctionName=fn))
    cfg = lam.get_function_event_invoke_config(FunctionName=fn)
    assert cfg.get("MaximumRetryAttempts") == attempts, (
        f"MaximumRetryAttempts did not round-trip on {fn}: expected {attempts}, got "
        f"{cfg.get('MaximumRetryAttempts')!r}"
    )
    stored = cfg.get("DestinationConfig", {}).get("OnFailure", {}).get("Destination")
    assert stored == destination_arn, (
        f"the OnFailure destination did not round-trip on {fn}: expected {destination_arn}, got "
        f"{stored!r}"
    )


def _invoke_async(lam, fn: str, marker: str) -> None:
    resp = lam.invoke(
        FunctionName=fn,
        InvocationType="Event",
        Payload=json.dumps({"marker": marker}).encode(),
    )
    assert resp["StatusCode"] == 202, (
        f"an asynchronous Invoke must be accepted with 202, {fn} returned {resp['StatusCode']}"
    )


def _receive(sqs, url: str, wait_s: int = 1) -> list[dict]:
    """Receive up to 10 messages, delete them, and return their parsed bodies with a receive
    timestamp attached. A body that is not JSON fails loudly rather than being skipped."""
    got = sqs.receive_message(
        QueueUrl=url,
        MaxNumberOfMessages=10,
        WaitTimeSeconds=wait_s,
        VisibilityTimeout=60,
    )
    out = []
    for msg in got.get("Messages", []):
        try:
            body = json.loads(msg["Body"])
        except ValueError:
            raise AssertionError(
                f"queue {url} delivered a non-JSON body: {msg['Body'][:300]!r}"
            ) from None
        body["seen_at"] = time.monotonic()
        out.append(body)
        sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _pump(sqs, count_url: str, dests: dict[str, str], *, timeout_s: float):
    """Drain the counting queue and each destination queue until every destination has produced its
    failure record. RAISES on the deadline, naming what was still missing."""
    attempts: dict[str, list[dict]] = collections.defaultdict(list)
    records: dict[str, dict] = {}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for body in _receive(sqs, count_url, wait_s=2):
            attempts[body["marker"]].append(body)
        for label, url in dests.items():
            if label in records:
                continue
            for body in _receive(sqs, url, wait_s=1):
                records.setdefault(label, body)
        if len(records) == len(dests):
            return attempts, records
    missing = sorted(set(dests) - set(records))
    counts = {k: len(v) for k, v in attempts.items()}
    raise AssertionError(
        f"no OnFailure record arrived for {missing} within {timeout_s:.0f}s; attempts counted on "
        f"the side channel so far: {counts}"
    )


def _drain_for(sqs, url: str, seconds: float) -> list[dict]:
    """Keep draining `url` for a calibrated window and return everything that arrived."""
    deadline = time.monotonic() + seconds
    extra: list[dict] = []
    while time.monotonic() < deadline:
        extra.extend(_receive(sqs, url, wait_s=5))
    return extra


def _create_execution_role(ctx, iam, queue_arns: list[str]) -> str:
    """This check's own execution role, granted sqs:SendMessage on exactly the queues this check
    creates — named, never wildcarded."""
    role_name = ctx.unique_name("sim2real-behav-retry-role-")
    trust = {
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
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))

    inline = "send-to-check-queues"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=inline,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["sqs:SendMessage", "sqs:GetQueueAttributes"],
                        "Resource": queue_arns,
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=inline))
    return role["Role"]["Arn"]


def _create_function(ctx, lam, **kwargs):
    """CreateFunction, retrying only the documented role-propagation refusal; raises on deadline."""
    name = kwargs["FunctionName"]
    ctx.on_cleanup(lambda: _delete_function(ctx, lam, name))
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("InvalidParameterValueException", "ResourceConflictException"):
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateFunction({name}) never succeeded within 90s; last error {last}")


def _delete_function(ctx, lam, name: str) -> None:
    lam.delete_function(FunctionName=name)
    ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")


def _wait_active(lam, name: str, timeout_s: float = 120.0) -> dict:
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Failed":
            raise AssertionError(
                f"{name} entered State=Failed: {cfg.get('StateReasonCode')} {cfg.get('StateReason')}"
            )
        return cfg

    return _poll_until(
        _probe,
        lambda cfg: cfg.get("State") == "Active",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"{name} reaching State=Active",
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Bounded retry with a deadline. RAISES on timeout, never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
