"""batch-item-failures-ignored-without-functionresponsetypes."""

# AWS behaviors this check relies on:
#   H1  With FunctionResponseTypes=["ReportBatchItemFailures"], a batchItemFailures response returns
#       ONLY the named message to the queue; the other four are deleted and never seen again.
#   H2  WITHOUT FunctionResponseTypes, a handler that returns normally has its whole batch deleted —
#       the batchItemFailures body is inert. The alternative (the whole batch is retried) would
#       show up as five second sightings on the counting queue, which this check also measures.
#   H3  maxReceiveCount=3 with VisibilityTimeout=10 means the returned message is delivered at most
#       3 times before SQS moves it to the redrive target, so sightings are bounded by 3.
#   H4  Both event source mappings reach State=Enabled within 180 s and start polling promptly, so
#       the two arms are genuinely concurrent.
#   H5  event["Records"][i]["messageId"] is the identifier batchItemFailures expects
#       (itemIdentifier), and rec["attributes"]["ApproximateReceiveCount"] is present.

from __future__ import annotations

import collections
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-item-failures-ignored-without-functionresponsetypes"
GROUP = "event-source-mapping"
SERVICES = ["lambda", "sqs"]

_BATCH = 5
_MAX_RECEIVE = 3
_VISIBILITY_S = 10
_POISON = "poison"
_OK_BODIES = [f"ok-{i}" for i in range(_BATCH - 1)]

# The `boto3.client` below is inside the DEPLOYED payload: it runs in the target's own Lambda
# runtime against the target's own ambient endpoint, not in the check process, so it does not use
# ctx.client.
_HANDLER = """\
import json
import os

import boto3

_SQS = boto3.client("sqs")
_COUNT_QUEUE = os.environ["COUNT_QUEUE_URL"]
_ARM = os.environ["ARM"]


def handler(event, context):
    failures = []
    for rec in event["Records"]:
        _SQS.send_message(
            QueueUrl=_COUNT_QUEUE,
            MessageBody=json.dumps({
                "arm": _ARM,
                "body": rec["body"],
                "message_id": rec["messageId"],
                "receive_count": rec.get("attributes", {}).get("ApproximateReceiveCount"),
            }),
        )
        if rec["body"] == "poison":
            failures.append({"itemIdentifier": rec["messageId"]})
    return {"batchItemFailures": failures}
"""


# timing:real-time — visibility: 10 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
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
    """A batchItemFailures response is honoured ONLY when the mapping declares
    FunctionResponseTypes=ReportBatchItemFailures; without it the identical body is inert and the whole
    batch is deleted, measured at a side-channel queue against a twin arm that does redeliver.
    """
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")

    count_url, count_arn = _create_queue(ctx, sqs, "count-")
    dlq_a_url, dlq_a_arn = _create_queue(ctx, sqs, "dlq-a-")
    dlq_b_url, dlq_b_arn = _create_queue(ctx, sqs, "dlq-b-")
    src_a_url, src_a_arn = _create_queue(ctx, sqs, "src-a-", redrive_to=dlq_a_arn)
    src_b_url, src_b_arn = _create_queue(ctx, sqs, "src-b-", redrive_to=dlq_b_arn)

    role_arn = _create_execution_role(
        ctx, iam, send_to=[count_arn], consume=[src_a_arn, src_b_arn]
    )

    fn_a = _deploy(ctx, lam, role_arn, count_url, "report")
    fn_b = _deploy(ctx, lam, role_arn, count_url, "noreport")

    esm_a = _create_esm(ctx, lam, fn_a, src_a_arn, report_failures=True)
    esm_b = _create_esm(ctx, lam, fn_b, src_b_arn, report_failures=False)
    _wait_esm_enabled(lam, esm_a)
    _wait_esm_enabled(lam, esm_b)

    # Same instant, identical payloads, one difference: FunctionResponseTypes.
    for url in (src_a_url, src_b_url):
        for body in [*_OK_BODIES, _POISON]:
            sqs.send_message(QueueUrl=url, MessageBody=body)

    # ---- wait for the demonstrated control: arm A's poison must reach its redrive target ----
    sightings, dead_a = _pump_until_dlq(
        sqs, count_url, dlq_a_url, timeout_s=420.0
    )
    assert [m["body"] for m in dead_a] == [_POISON], (
        f"arm A's redrive target must receive exactly the poison message, it received "
        f"{[m['body'] for m in dead_a]}"
    )

    arm_a = collections.Counter(m["body"] for m in sightings if m["arm"] == "report")
    arm_b = collections.Counter(m["body"] for m in sightings if m["arm"] == "noreport")

    # ---- arm A: only the reported item comes back ----
    for body in _OK_BODIES:
        assert arm_a[body] == 1, (
            f"arm A named only {_POISON!r} in batchItemFailures, so {body!r} must be delivered "
            f"exactly once; the handler saw it {arm_a[body]} time(s). Full arm A tally: {dict(arm_a)}"
        )
    assert arm_a[_POISON] >= 2, (
        f"arm A declared FunctionResponseTypes=ReportBatchItemFailures and named {_POISON!r}, so it "
        f"must be redelivered at least once; the handler saw it {arm_a[_POISON]} time(s). Full "
        f"tally: {dict(arm_a)}"
    )
    assert arm_a[_POISON] <= _MAX_RECEIVE, (
        f"the source queue's redrive policy caps delivery at maxReceiveCount={_MAX_RECEIVE}, but "
        f"arm A's handler saw {_POISON!r} {arm_a[_POISON]} time(s)"
    )

    # ---- arm B: the identical response body changed nothing ----
    for body in [*_OK_BODIES, _POISON]:
        assert arm_b[body] == 1, (
            f"arm B's mapping declares no FunctionResponseTypes, so its batchItemFailures response "
            f"must be ignored and {body!r} delivered exactly once; the handler saw it "
            f"{arm_b[body]} time(s). Full arm B tally: {dict(arm_b)}"
        )
    assert sum(arm_b.values()) == _BATCH, (
        f"arm B must see exactly {_BATCH} deliveries in total, it saw {sum(arm_b.values())}: "
        f"{dict(arm_b)}"
    )

    # ---- arm B's redrive target must be empty, over the window arm A needed to fill its own ----
    quiet_s = max(_VISIBILITY_S * (_MAX_RECEIVE + 1), 60)
    late = _drain_for(sqs, dlq_b_url, quiet_s)
    assert late == [], (
        f"arm B's redrive target received {len(late)} message(s) — "
        f"{[m.get('body') or m.get('raw') for m in late]} — although its mapping does not declare "
        f"FunctionResponseTypes, so nothing should ever have been returned to the source queue"
    )


# ===== helpers =====

def _make_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _create_queue(ctx, sqs, label: str, *, redrive_to: str | None = None) -> tuple[str, str]:
    name = ctx.unique_name(f"sim2real-behav-bif-{label}")
    attributes = {"VisibilityTimeout": str(_VISIBILITY_S)}
    if redrive_to:
        attributes["RedrivePolicy"] = json.dumps(
            {"deadLetterTargetArn": redrive_to, "maxReceiveCount": _MAX_RECEIVE}
        )
    created = sqs.create_queue(QueueName=name, Attributes=attributes, tags={"sim2real": CHECK})
    url = created["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return url, arn


def _deploy(ctx, lam, role_arn: str, count_url: str, arm: str) -> str:
    fn = ctx.unique_name(f"sim2real-behav-bif-{arm}-")
    _create_function(
        ctx,
        lam,
        FunctionName=fn,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _make_zip({"index.py": _HANDLER})},
        Environment={"Variables": {"COUNT_QUEUE_URL": count_url, "ARM": arm}},
        MemorySize=256,
        Timeout=_VISIBILITY_S,
        Tags={"sim2real": CHECK, "arm": arm},
    )
    _wait_active(lam, fn)
    return fn


def _create_esm(ctx, lam, fn: str, source_arn: str, *, report_failures: bool) -> str:
    kwargs = {
        "FunctionName": fn,
        "EventSourceArn": source_arn,
        "BatchSize": _BATCH,
        "Enabled": True,
        "MaximumBatchingWindowInSeconds": 0,
    }
    if report_failures:
        kwargs["FunctionResponseTypes"] = ["ReportBatchItemFailures"]
    created = lam.create_event_source_mapping(**kwargs)
    uuid = created["UUID"]
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=uuid))
    stored = created.get("FunctionResponseTypes")
    if report_failures:
        assert stored == ["ReportBatchItemFailures"], (
            f"the mapping for {fn} must store FunctionResponseTypes=['ReportBatchItemFailures'], "
            f"CreateEventSourceMapping echoed {stored!r}"
        )
    else:
        # No default supplied: an absent key and an empty list are both "not declared", and the
        # whole point of this arm is that nothing was declared.
        assert not stored, (
            f"the control arm's mapping for {fn} must declare NO FunctionResponseTypes, "
            f"CreateEventSourceMapping echoed {stored!r}"
        )
    return uuid


def _wait_esm_enabled(lam, uuid: str, timeout_s: float = 180.0) -> dict:
    def _probe():
        esm = lam.get_event_source_mapping(UUID=uuid)
        if esm.get("State") in ("Deleting", "Disabled"):
            raise AssertionError(
                f"mapping {uuid} went to State={esm['State']}: {esm.get('StateTransitionReason')}"
            )
        return esm

    return _poll_until(
        _probe,
        lambda esm: esm.get("State") == "Enabled",
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"event source mapping {uuid} reaching State=Enabled",
    )


def _receive(sqs, url: str, wait_s: int = 2) -> list[dict]:
    """Receive up to 10 messages, delete them, and return parsed bodies. A non-JSON body is kept as
    {"raw": ...} because a redrive target carries the ORIGINAL plain-text body, not JSON."""
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
            if not isinstance(body, dict):
                body = {"raw": msg["Body"], "body": msg["Body"]}
        except ValueError:
            body = {"raw": msg["Body"], "body": msg["Body"]}
        out.append(body)
        sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _pump_until_dlq(sqs, count_url: str, dlq_url: str, *, timeout_s: float):
    """Drain the counting queue until arm A's redrive target produces a message. RAISES on the
    deadline, naming the tally so far — a poll that returned its last value would let a target with
    no redelivery path pass the assertions that follow."""
    sightings: list[dict] = []
    dead: list[dict] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        sightings.extend(_receive(sqs, count_url, wait_s=2))
        dead.extend(_receive(sqs, dlq_url, wait_s=1))
        if dead:
            # Give the counting queue a last sweep so no in-flight sighting is missed.
            settle = time.monotonic() + 20.0
            while time.monotonic() < settle:
                sightings.extend(_receive(sqs, count_url, wait_s=5))
            return sightings, dead
    tally = collections.Counter((m.get("arm"), m.get("body")) for m in sightings)
    raise AssertionError(
        f"arm A's redrive target received nothing within {timeout_s:.0f}s, so no redelivery was "
        f"ever demonstrated and the arm B absence assertion would be unbounded; sightings so far: "
        f"{dict(tally)}"
    )


def _drain_for(sqs, url: str, seconds: float) -> list[dict]:
    """Keep draining `url` for a calibrated window and return everything that arrived."""
    deadline = time.monotonic() + seconds
    extra: list[dict] = []
    while time.monotonic() < deadline:
        extra.extend(_receive(sqs, url, wait_s=5))
    return extra


def _create_execution_role(ctx, iam, *, send_to: list[str], consume: list[str]) -> str:
    """This check's own execution role, scoped to exactly the queues this check creates."""
    role_name = ctx.unique_name("sim2real-behav-bif-role-")
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

    inline = "queues-this-check-created"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=inline,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": send_to},
                    {
                        "Effect": "Allow",
                        "Action": [
                            "sqs:ReceiveMessage",
                            "sqs:DeleteMessage",
                            "sqs:GetQueueAttributes",
                            "sqs:ChangeMessageVisibility",
                        ],
                        "Resource": consume,
                    },
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
