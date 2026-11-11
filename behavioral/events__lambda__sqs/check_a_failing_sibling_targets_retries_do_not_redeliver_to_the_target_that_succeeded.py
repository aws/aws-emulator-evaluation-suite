"""a-failing-sibling-targets-retries-do-not-redeliver-to-the-target-that-succeeded."""

# Lambda's own asynchronous retry is off for the function (MaximumRetryAttempts=0), so the first
# event's failure is terminal and the restore leg cannot see that event re-run by the repaired code.
# Docs: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-monitoring.html (AWS/Events
# metric table); https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rule-dlq.html

from __future__ import annotations

import collections
import io
import json
import time
import uuid
import zipfile
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "a-failing-sibling-targets-retries-do-not-redeliver-to-the-target-that-succeeded"
GROUP = "error-propagation"
SERVICES = ["events", "lambda", "sqs"]

_SOURCE = "sim2real.nd.sibling"
_DETAIL_TYPE = "SiblingTargetProbe"

#: The REPAIRED body, used only in the restore leg: it reports what it processed.
_FN_SRC_OK = """
import json, os, boto3
def handler(event, context):
    boto3.client("sqs").send_message(
        QueueUrl=os.environ["RESULT_QUEUE_URL"],
        MessageBody=json.dumps({"nonce": event.get("detail", {}).get("nonce")}),
    )
    return {"ok": True}
"""

#: The FAILING body. An unhandled exception is the strongest failure a Lambda target can produce,
#: and the point of this check is that EventBridge cannot see it.
_FN_SRC_THROW = """
def handler(event, context):
    raise RuntimeError("sim2real-forced-target-failure")
"""


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    """A bounded retry that RAISES on its deadline; never returns its last value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _zip_bytes(src, name="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo(name)
        info.external_attr = 0o755 << 16
        zf.writestr(info, src)
    return buf.getvalue()


def _make_queue(ctx, name, *, service_principal, source_arn_like, check_tag):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=name, tags={"sim2real-check": check_tag})["QueueUrl"]
    ctx.on_cleanup(lambda u=url: ctx.client("sqs").delete_queue(QueueUrl=u))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    sqs.set_queue_attributes(
        QueueUrl=url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowService",
                            "Effect": "Allow",
                            "Principal": {"Service": service_principal},
                            "Action": "sqs:SendMessage",
                            "Resource": arn,
                            "Condition": {"ArnLike": {"aws:SourceArn": source_arn_like}},
                        }
                    ],
                }
            )
        },
    )
    return url, arn


def _drain(ctx, url, *, seconds):
    """Receive and delete every message that arrives within `seconds`; return them."""
    sqs = ctx.client("sqs")
    out = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5, MessageAttributeNames=["All"]
        )
        for msg in resp.get("Messages", []):
            out.append(msg)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _queue_depth(ctx, url):
    attrs = ctx.client("sqs").get_queue_attributes(
        QueueUrl=url,
        AttributeNames=[
            "ApproximateNumberOfMessages",
            "ApproximateNumberOfMessagesNotVisible",
            "ApproximateNumberOfMessagesDelayed",
        ],
    )["Attributes"]
    return sum(int(v) for v in attrs.values())


def _metric_sum(ctx, metric, dims, *, since):
    resp = ctx.client("cloudwatch").get_metric_statistics(
        Namespace="AWS/Events",
        MetricName=metric,
        Dimensions=[{"Name": k, "Value": v} for k, v in sorted(dims.items())],
        StartTime=since,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=2),
        Period=60,
        Statistics=["Sum"],
    )
    points = resp.get("Datapoints", [])
    return sum(p["Sum"] for p in points)


def _ensure_lambda_role(ctx, name, check_tag):
    iam = ctx.client("iam")
    trust = json.dumps(
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
    )
    try:
        arn = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=trust,
            Tags=[{"Key": "sim2real-check", "Value": check_tag}],
        )["Role"]["Arn"]
        ctx.on_cleanup(lambda n=name: _delete_role(ctx, n))
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "EntityAlreadyExists":
            raise
        arn = iam.get_role(RoleName=name)["Role"]["Arn"]  # create-or-adopt
    iam.put_role_policy(
        RoleName=name,
        PolicyName="sim2real-send",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}],
            }
        ),
    )
    return arn


def _delete_role(ctx, name):
    iam = ctx.client("iam")
    for pol in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=name, PolicyName=pol)
    iam.delete_role(RoleName=name)


# ===== the check =====
# timing:real-time — metric: 60 s https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-monitoring.html
@tags(
    "axis:negative-delivery",
    "cap:c4",
    "concern:eventing",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A Lambda target that throws is not a failed target invocation as far as EventBridge is
    concerned: the healthy sibling target gets exactly one copy, the failing target's DLQ stays
    empty, and the rule's own counters report BOTH target invocations as successful."""
    events = ctx.client("events")
    lam = ctx.client("lambda")
    account = ctx.client("sts").get_caller_identity()["Account"]
    check_tag = CHECK
    suffix = uuid.uuid4().hex[:10]

    bus = ctx.unique_name("sim2real-nd-sib-bus-")
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real-check", "Value": check_tag}])
    ctx.on_cleanup(lambda: ctx.client("events").delete_event_bus(Name=bus))
    rule_arn_like = f"arn:*:events:{ctx.region}:{account}:rule/{bus}/*"

    healthy_url, healthy_arn = _make_queue(
        ctx,
        f"sim2real-nd-sib-ok-{suffix}",
        service_principal="events.amazonaws.com",
        source_arn_like=rule_arn_like,
        check_tag=check_tag,
    )
    dlq_url, dlq_arn = _make_queue(
        ctx,
        f"sim2real-nd-sib-dlq-{suffix}",
        service_principal="events.amazonaws.com",
        source_arn_like=rule_arn_like,
        check_tag=check_tag,
    )
    result_url, _ = _make_queue(
        ctx,
        f"sim2real-nd-sib-result-{suffix}",
        service_principal="lambda.amazonaws.com",
        source_arn_like=f"arn:*:lambda:{ctx.region}:{account}:function:*",
        check_tag=check_tag,
    )

    role_arn = _ensure_lambda_role(ctx, f"sim2real-nd-sib-role-{suffix}", check_tag)
    fn_name = ctx.unique_name("sim2real-nd-sib-fn-")
    fn_arn = _create_function(ctx, lam, fn_name, role_arn, result_url, check_tag, _FN_SRC_THROW)

    # Lambda's OWN async retry is switched off, so the first event's failure is terminal and the
    # restore leg below cannot see the FIRST event re-run by the repaired code.
    lam.put_function_event_invoke_config(FunctionName=fn_name, MaximumRetryAttempts=0)

    # Sanity control: prove the target really does fail. A SYNCHRONOUS invoke returns HTTP 200
    # with FunctionError="Unhandled" -- the failure is real and reported, which is what makes
    # EventBridge's silence below meaningful.
    direct = ctx.client("lambda").invoke(
        FunctionName=fn_name, InvocationType="RequestResponse", Payload=b"{}"
    )
    assert direct.get("FunctionError") == "Unhandled", (
        f"the target function did not fail when invoked directly "
        f"(FunctionError={direct.get('FunctionError')!r}, StatusCode={direct.get('StatusCode')!r}); "
        f"with a healthy target the rest of this check would prove nothing"
    )

    rule = ctx.unique_name("sim2real-nd-sib-rule-")
    rule_arn = events.put_rule(
        Name=rule,
        EventBusName=bus,
        EventPattern=json.dumps({"source": [_SOURCE], "detail-type": [_DETAIL_TYPE]}),
        State="ENABLED",
        Tags=[{"Key": "sim2real-check", "Value": check_tag}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: _teardown_rule(ctx, bus, rule, ["ok", "bad"]))
    lam.add_permission(
        FunctionName=fn_name,
        StatementId="sim2real-events",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )
    resp = events.put_targets(
        Rule=rule,
        EventBusName=bus,
        Targets=[
            {"Id": "ok", "Arn": healthy_arn},
            {
                "Id": "bad",
                "Arn": fn_arn,
                "RetryPolicy": {"MaximumRetryAttempts": 2, "MaximumEventAgeInSeconds": 86400},
                "DeadLetterConfig": {"Arn": dlq_arn},
            },
        ],
    )
    assert resp.get("FailedEntryCount") == 0, (
        f"put_targets did not attach BOTH targets, so the sibling relationship under test does not "
        f"exist: {resp.get('FailedEntries')!r}"
    )
    ids = sorted(t["Id"] for t in events.list_targets_by_rule(Rule=rule, EventBusName=bus)["Targets"])
    assert ids == ["bad", "ok"], (
        f"ListTargetsByRule reports targets {ids!r} on {rule}, expected ['bad', 'ok'] — the whole "
        f"claim is about two siblings on ONE rule"
    )

    window_start = datetime.now(timezone.utc) - timedelta(minutes=1)
    first = f"first-{uuid.uuid4().hex[:12]}"
    t0 = time.monotonic()
    put = events.put_events(
        Entries=[
            {
                "EventBusName": bus,
                "Source": _SOURCE,
                "DetailType": _DETAIL_TYPE,
                "Detail": json.dumps({"nonce": first}),
            }
        ]
    )
    assert put.get("FailedEntryCount") == 0, (
        f"PutEvents did not accept the event, so nothing below is attributable: {put!r}"
    )

    # The healthy sibling IS the positive control: it does the same work at the same moment on the
    # same rule match, and its arrival measures L.
    ok_msgs = _poll_until(
        lambda: _drain(ctx, healthy_url, seconds=6),
        lambda msgs: any(first in m["Body"] for m in msgs),
        timeout_s=180,
        interval_s=0,
        description=(
            f"the healthy sibling target delivered {first!r} to {healthy_url} — the positive leg of "
            f"this negative-delivery check and the measurement of L"
        ),
    )
    latency = max(time.monotonic() - t0, 1.0)
    counts = collections.Counter(json.loads(m["Body"])["detail"]["nonce"] for m in ok_msgs)
    assert counts == {first: 1}, (
        f"the healthy target received {dict(counts)!r} on the first drain, expected exactly "
        f"{{{first!r}: 1}} — a duplicate here already means the rule match was re-run"
    )

    # THE NEGATIVE, part 1: nothing is dead-lettered, because EventBridge's asynchronous Invoke of the
    # Lambda target succeeded and the exception happened afterwards, out of EventBridge's sight.
    hold = max(3 * latency, 60.0)
    dead = _drain(ctx, dlq_url, seconds=hold)
    assert dead == [], (
        f"the DLQ received {len(dead)} message(s) during a {hold:.0f}s hold even though the only "
        f"failure was INSIDE the Lambda target: "
        f"{[(m['Body'][:80], {k: v.get('StringValue') for k, v in (m.get('MessageAttributes') or {}).items()}) for m in dead]!r}"
    )
    assert _queue_depth(ctx, dlq_url) == 0, (
        f"the DLQ reports depth {_queue_depth(ctx, dlq_url)} behind an empty receive — the second "
        f"independent observable disagrees with the first"
    )

    # THE NEGATIVE, part 2: no second copy at the target that already succeeded.
    extra = _drain(ctx, healthy_url, seconds=max(2 * latency, 20.0))
    assert extra == [], (
        f"the healthy target received {len(extra)} further copy/copies while its sibling target's "
        f"invocation was failing internally: {[m['Body'][:100] for m in extra]!r} — one rule match "
        f"is one delivery per target"
    )
    assert _queue_depth(ctx, healthy_url) == 0, (
        f"the healthy queue reports depth {_queue_depth(ctx, healthy_url)} behind an empty receive — "
        f"the second independent observable disagrees with the first"
    )

    # The rule-level counters, which DO sum across targets: BOTH invocations are recorded, and BOTH
    # are recorded as successful.
    def _sum(metric):
        return _metric_sum(ctx, metric, {"EventBusName": bus, "RuleName": rule}, since=window_start)

    attempts = _poll_until(
        lambda: _sum("InvocationAttempts"),
        lambda n: n >= 2,
        timeout_s=300,
        interval_s=15,
        description=(
            f"AWS/Events InvocationAttempts for {rule} reached 2 — one invocation per target on a "
            f"single rule match"
        ),
    )
    assert attempts == 2, (
        f"InvocationAttempts Sum={attempts} for rule {rule}, expected exactly 2 (one per target). "
        f"More would mean EventBridge retried something"
    )
    successes = _sum("SuccessfulInvocationAttempts")
    assert successes == 2, (
        f"SuccessfulInvocationAttempts Sum={successes} for rule {rule}, expected exactly 2 — "
        f"EventBridge counts the throwing Lambda target's asynchronous Invoke as a SUCCESS"
    )
    retries = _sum("RetryInvocationAttempts")
    assert retries == 0, (
        f"RetryInvocationAttempts Sum={retries} for rule {rule}, expected 0 — there is no target "
        f"failure for EventBridge to retry, so MaximumRetryAttempts=2 is never exercised"
    )
    failed = _sum("FailedInvocations")
    assert failed == 0, (
        f"FailedInvocations Sum={failed} for rule {rule}, expected 0 — the failure is inside the "
        f"function, not in the invocation"
    )
    triggered = _sum("TriggeredRules")
    assert triggered == 1, (
        f"TriggeredRules Sum={triggered} for rule {rule}, expected exactly 1 — one event, one match"
    )

    # Restore the one broken thing (the function body) and demand the NEXT event through both
    # targets, with no late replay of the first.
    lam.update_function_code(FunctionName=fn_name, ZipFile=_zip_bytes(_FN_SRC_OK))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=fn_name)["LastUpdateStatus"],
        lambda st: st == "Successful",
        timeout_s=120,
        interval_s=3,
        description=f"function {fn_name} finished updating to the repaired body",
    )
    second = f"second-{uuid.uuid4().hex[:12]}"
    again = events.put_events(
        Entries=[
            {
                "EventBusName": bus,
                "Source": _SOURCE,
                "DetailType": _DETAIL_TYPE,
                "Detail": json.dumps({"nonce": second}),
            }
        ]
    )
    assert again.get("FailedEntryCount") == 0, f"the restore-leg PutEvents was refused: {again!r}"
    ran = _poll_until(
        lambda: _drain(ctx, result_url, seconds=8),
        lambda msgs: len(msgs) >= 1,
        timeout_s=240,
        interval_s=0,
        description=(
            f"with the repaired body in place, the previously failing target ran and wrote to "
            f"{result_url}"
        ),
    )
    ran_nonces = sorted(json.loads(m["Body"])["nonce"] for m in ran)
    assert ran_nonces == [second], (
        f"the repaired target processed {ran_nonces!r}, expected exactly [{second!r}] — the first "
        f"event's failure was terminal (Lambda MaximumRetryAttempts=0) and EventBridge never "
        f"retried it, so it must never be processed late"
    )
    ok_again = _drain(ctx, healthy_url, seconds=max(2 * latency, 20.0))
    ok_nonces = sorted(json.loads(m["Body"])["detail"]["nonce"] for m in ok_again)
    assert ok_nonces == [second], (
        f"the healthy target received {ok_nonces!r} after the repair, expected exactly [{second!r}]"
    )


def _create_function(ctx, lam, name, role_arn, result_queue_url, check_tag, source):
    def _create():
        return lam.create_function(
            FunctionName=name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": _zip_bytes(source)},
            Timeout=15,
            Environment={"Variables": {"RESULT_QUEUE_URL": result_queue_url}},
            Tags={"sim2real-check": check_tag},
        )

    created = _poll_until(
        lambda: _create_or_error(_create),
        lambda r: isinstance(r, dict),
        timeout_s=120,
        interval_s=5,
        description=f"create_function {name} succeeded (IAM role propagation)",
    )
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=name))
    _poll_until(
        lambda: ctx.client("lambda").get_function_configuration(FunctionName=name)["State"],
        lambda s: s == "Active",
        timeout_s=120,
        interval_s=3,
        description=f"function {name} reached State=Active",
    )
    return created["FunctionArn"]


def _create_or_error(fn):
    """Return fn()'s result, or the error code of an InvalidParameterValue or AccessDenied refusal."""
    try:
        return fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("InvalidParameterValueException", "AccessDeniedException"):
            return code
        raise


def _teardown_rule(ctx, bus, rule, ids):
    events = ctx.client("events")
    events.remove_targets(Rule=rule, EventBusName=bus, Ids=ids, Force=True)
    events.delete_rule(Name=rule, EventBusName=bus, Force=True)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
