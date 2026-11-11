"""invocations-sent-to-dlq-counts-only-the-rule-whose-target-failed."""

from __future__ import annotations

import io
import json
import time
import uuid
import zipfile
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invocations-sent-to-dlq-counts-only-the-rule-whose-target-failed"
GROUP = "error-propagation"
SERVICES = ["cloudwatch", "events", "sqs"]

_SOURCE = "sim2real.nd.dlqattrib"
_DETAIL_TYPE = "DlqAttributionProbe"
_ENVELOPE_KEYS = ("id", "version", "time", "region", "account", "source", "detail-type", "detail")

_FN_SRC = """
import json, os, boto3
def handler(event, context):
    boto3.client("sqs").send_message(
        QueueUrl=os.environ["RESULT_QUEUE_URL"],
        MessageBody=json.dumps({"nonce": event.get("detail", {}).get("nonce")}),
    )
    return {"ok": True}
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
    """`.get("Messages", [])` feeds a loop whose result is asserted by exact count — the sanctioned
    polarity for an empty default."""
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


def _metric(ctx, metric, dims, *, since):
    resp = ctx.client("cloudwatch").get_metric_statistics(
        Namespace="AWS/Events",
        MetricName=metric,
        Dimensions=[{"Name": k, "Value": v} for k, v in sorted(dims.items())],
        StartTime=since,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=2),
        Period=60,
        Statistics=["Sum"],
    )
    points = resp.get("Datapoints", [])  # polarity: feeds asserted values
    return sum(p["Sum"] for p in points), len(points)


def _ensure_lambda_role(ctx, name, check_tag):
    iam = ctx.client("iam")
    try:
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


def _put_targets_ok(events, bus, rule, targets):
    resp = events.put_targets(Rule=rule, EventBusName=bus, Targets=targets)
    assert resp.get("FailedEntryCount") == 0, (
        f"put_targets on {rule} reported failures, so the wiring under test does not exist: "
        f"{resp.get('FailedEntries')!r}"
    )


def _teardown_rule(ctx, bus, rule, ids):
    events = ctx.client("events")
    events.remove_targets(Rule=rule, EventBusName=bus, Ids=ids, Force=True)
    events.delete_rule(Name=rule, EventBusName=bus, Force=True)


# ===== the check =====
# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html
@tags(
    "axis:negative-delivery",
    "cap:c2",
    "concern:eventing",
    "concern:metrics",
    "dp:api",
    "plane:data", "timing:real-time",
)
def run(ctx) -> None:
    """One event, two rules, one shared DLQ: the DLQ holds exactly one copy, names the failing rule,
    carries the envelope the healthy twin received, and AWS/Events attributes InvocationsSentToDlq
    to the failing rule only (under EventBusName + RuleName on a custom bus)."""
    events = ctx.client("events")
    lam = ctx.client("lambda")
    account = ctx.client("sts").get_caller_identity()["Account"]
    check_tag = CHECK
    suffix = uuid.uuid4().hex[:10]
    pattern = json.dumps({"source": [_SOURCE], "detail-type": [_DETAIL_TYPE]})

    bus = ctx.unique_name("sim2real-nd-dlqa-bus-")
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real-check", "Value": check_tag}])
    ctx.on_cleanup(lambda: ctx.client("events").delete_event_bus(Name=bus))
    rule_arn_like = f"arn:*:events:{ctx.region}:{account}:rule/{bus}/*"

    ok_url, ok_arn = _make_queue(
        ctx,
        f"sim2real-nd-dlqa-ok-{suffix}",
        service_principal="events.amazonaws.com",
        source_arn_like=rule_arn_like,
        check_tag=check_tag,
    )
    dlq_url, dlq_arn = _make_queue(
        ctx,
        f"sim2real-nd-dlqa-dlq-{suffix}",
        service_principal="events.amazonaws.com",
        source_arn_like=rule_arn_like,
        check_tag=check_tag,
    )
    result_url, _ = _make_queue(
        ctx,
        f"sim2real-nd-dlqa-result-{suffix}",
        service_principal="lambda.amazonaws.com",
        source_arn_like=f"arn:*:lambda:{ctx.region}:{account}:function:*",
        check_tag=check_tag,
    )

    role_arn = _ensure_lambda_role(ctx, f"sim2real-nd-dlqa-role-{suffix}", check_tag)
    fn_name = ctx.unique_name("sim2real-nd-dlqa-fn-")
    fn_arn = _create_function(ctx, lam, fn_name, role_arn, result_url, check_tag)
    # The break is STRUCTURAL: no resource policy exists on the function, so EventBridge cannot
    # invoke it and, per the docs, does not even retry. Nothing waits for this.
    missing = _get_policy_or_none(lam, fn_name)
    assert missing is None, (
        f"the function {fn_name} already carries a resource policy ({missing!r}), so the "
        f"NO_PERMISSIONS failure this check depends on may not occur"
    )

    ok_rule = ctx.unique_name("sim2real-nd-dlqa-ok-")
    ok_rule_arn = events.put_rule(
        Name=ok_rule,
        EventBusName=bus,
        EventPattern=pattern,
        State="ENABLED",
        Tags=[{"Key": "sim2real-check", "Value": check_tag}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: _teardown_rule(ctx, bus, ok_rule, ["t"]))
    _put_targets_ok(
        events,
        bus,
        ok_rule,
        [{"Id": "t", "Arn": ok_arn, "DeadLetterConfig": {"Arn": dlq_arn}}],
    )

    bad_rule = ctx.unique_name("sim2real-nd-dlqa-bad-")
    bad_rule_arn = events.put_rule(
        Name=bad_rule,
        EventBusName=bus,
        EventPattern=pattern,
        State="ENABLED",
        Tags=[{"Key": "sim2real-check", "Value": check_tag}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: _teardown_rule(ctx, bus, bad_rule, ["t"]))
    _put_targets_ok(
        events,
        bus,
        bad_rule,
        [
            {
                "Id": "t",
                "Arn": fn_arn,
                "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
                "DeadLetterConfig": {"Arn": dlq_arn},
            }
        ],
    )

    window_start = datetime.now(timezone.utc) - timedelta(minutes=1)
    nonce = f"attrib-{uuid.uuid4().hex[:12]}"
    t0 = time.monotonic()
    put = events.put_events(
        Entries=[
            {
                "EventBusName": bus,
                "Source": _SOURCE,
                "DetailType": _DETAIL_TYPE,
                "Detail": json.dumps({"nonce": nonce}),
            }
        ]
    )
    assert put.get("FailedEntryCount") == 0, (
        f"PutEvents did not accept the event, so nothing below is attributable: {put!r}"
    )

    # The healthy twin: same bus, same pattern, same instant, same shared DLQ.
    ok_msgs = _poll_until(
        lambda: _drain(ctx, ok_url, seconds=6),
        lambda msgs: any(nonce in m["Body"] for m in msgs),
        timeout_s=180,
        interval_s=0,
        description=(
            f"the healthy rule {ok_rule} delivered {nonce!r} to {ok_url} — the positive leg, and the "
            f"source of the envelope the dead-lettered copy is compared against"
        ),
    )
    latency = max(time.monotonic() - t0, 1.0)
    assert len(ok_msgs) == 1, (
        f"the healthy queue holds {len(ok_msgs)} message(s) for one event, expected exactly 1: "
        f"{[m['Body'][:100] for m in ok_msgs]!r}"
    )
    good_envelope = json.loads(ok_msgs[0]["Body"])
    assert good_envelope["detail"]["nonce"] == nonce, (
        f"the healthy delivery carries nonce={good_envelope['detail'].get('nonce')!r}, expected "
        f"{nonce!r}: {good_envelope!r}"
    )
    assert good_envelope.get("id"), (
        f"the delivered envelope carries no service-generated `id` "
        f"(keys: {sorted(good_envelope)!r}) — the envelope-identity claim below has nothing to "
        f"compare, and an `id` no recording can carry is the point of it"
    )

    # The failing twin dead-letters. Per the docs there are NO retries for a permissions failure,
    # so this is the fastest leg, not the slowest.
    dead = _poll_until(
        lambda: _drain(ctx, dlq_url, seconds=8),
        lambda msgs: len(msgs) >= 1,
        timeout_s=180,
        interval_s=0,
        description=(
            f"the rule {bad_rule}, whose Lambda target has no invoke grant, dead-lettered the event "
            f"to the SHARED DLQ {dlq_url}"
        ),
    )
    assert len(dead) == 1, (
        f"the shared DLQ holds {len(dead)} message(s), expected exactly 1. Two would mean the "
        f"healthy rule {ok_rule} also dead-lettered a successful delivery: "
        f"{[m['Body'][:100] for m in dead]!r}"
    )
    attrs = dead[0].get("MessageAttributes", {})  # feeds exact-equality assertions below
    assert attrs.get("RULE_ARN", {}).get("StringValue") == bad_rule_arn, (
        f"the DLQ copy names RULE_ARN={attrs.get('RULE_ARN', {}).get('StringValue')!r}, expected the "
        f"FAILING rule {bad_rule_arn!r}. If it names {ok_rule_arn!r} the DLQ does not attribute a "
        f"failure to the rule that caused it, and a shared DLQ carries no diagnostic information"
    )
    assert attrs.get("TARGET_ARN", {}).get("StringValue") == fn_arn, (
        f"the DLQ copy names TARGET_ARN={attrs.get('TARGET_ARN', {}).get('StringValue')!r}, expected "
        f"{fn_arn!r}"
    )
    assert attrs.get("ERROR_CODE", {}).get("StringValue") == "NO_PERMISSIONS", (
        f"the DLQ copy names ERROR_CODE="
        f"{attrs.get('ERROR_CODE', {}).get('StringValue')!r}, expected 'NO_PERMISSIONS' for a target "
        f"with no invoke grant"
    )

    # The envelope identity. Same event, so every service-generated field must match the copy
    # the healthy twin received, including the service-generated `id` and `time`: the same event
    # fanned out, not a synthesised copy.
    dead_envelope = json.loads(dead[0]["Body"])
    mismatched = {
        k: (good_envelope.get(k), dead_envelope.get(k))
        for k in _ENVELOPE_KEYS
        if good_envelope.get(k) != dead_envelope.get(k)
    }
    assert mismatched == {}, (
        f"the dead-lettered envelope differs from the copy the healthy twin received on "
        f"{sorted(mismatched)!r} (expected, actual): {mismatched!r}. Both are the SAME PutEvents "
        f"entry fanned out to two rules, so a differing `id` or `time` means the DLQ copy was "
        f"synthesised rather than carried"
    )

    # THE ABSENCE, held for 2L (floor 10 s): the healthy rule's success is never also dead-lettered.
    # The later after-repair drain of the same DLQ re-checks it after the metric reads below.
    hold = max(2 * latency, 10.0)
    extra = _drain(ctx, dlq_url, seconds=hold)
    assert extra == [], (
        f"{len(extra)} further message(s) reached the shared DLQ during a {hold:.0f}s hold (2x the "
        f"{latency:.0f}s measured latency): {[m['Body'][:100] for m in extra]!r} — one event with "
        f"one failing target dead-letters exactly once"
    )
    assert _queue_depth(ctx, dlq_url) == 0, (
        f"the shared DLQ reports depth {_queue_depth(ctx, dlq_url)} behind an empty receive — the "
        f"second independent observable disagrees with the first"
    )

    # The SERVICE's own record of the non-delivery, attributed per rule. Both documented
    # spellings are probed because two AWS pages disagree.
    def _dlq_metric(rule):
        return {
            spelling: _metric(
                ctx, spelling, {"EventBusName": bus, "RuleName": rule}, since=window_start
            )[0]
            for spelling in ("InvocationsSentToDlq", "InvocationsSentToDLQ")
        }

    bad_counts = _poll_until(
        lambda: _dlq_metric(bad_rule),
        lambda counts: max(counts.values()) >= 1,
        timeout_s=300,
        interval_s=2,
        description=(
            f"AWS/Events recorded a sent-to-DLQ invocation for the failing rule {bad_rule} under at "
            f"least one of its two documented metric spellings"
        ),
    )
    assert max(bad_counts.values()) >= 1, (
        f"neither spelling carried a datapoint for the failing rule {bad_rule}: {bad_counts!r} — the "
        f"DLQ demonstrably received the event, so the service did not record its own non-delivery"
    )
    ok_good, _ = _metric(
        ctx,
        "SuccessfulInvocationAttempts",
        {"EventBusName": bus, "RuleName": ok_rule},
        since=window_start,
    )
    assert ok_good >= 1, (
        f"SuccessfulInvocationAttempts Sum={ok_good} for the healthy rule {ok_rule}, expected >=1. "
        f"This must hold before the next assertion means anything: the sent-to-DLQ metric is only "
        f"emitted when non-zero, so 'no datapoints for the healthy rule' would otherwise also be "
        f"what a target emitting no AWS/Events metrics produces"
    )
    ok_counts = _dlq_metric(ok_rule)
    assert max(ok_counts.values()) == 0, (
        f"the healthy rule {ok_rule} recorded {ok_counts!r} sent-to-DLQ invocations, expected 0 under "
        f"both spellings — its target succeeded, and a shared DLQ must not make its metrics move"
    )

    # RESTORE the one broken thing and demand the withheld capability.
    lam.add_permission(
        FunctionName=fn_name,
        StatementId="sim2real-events",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=bad_rule_arn,
    )
    released = None

    def _release():
        nonlocal released
        released = f"released-{uuid.uuid4().hex[:10]}"
        again = events.put_events(
            Entries=[
                {
                    "EventBusName": bus,
                    "Source": _SOURCE,
                    "DetailType": _DETAIL_TYPE,
                    "Detail": json.dumps({"nonce": released}),
                }
            ]
        )
        assert again.get("FailedEntryCount") == 0, f"the restore-leg PutEvents was refused: {again!r}"

    def _delivered_or_resend():
        # The new invoke grant propagates asynchronously: an event dead-lettered with
        # NO_PERMISSIONS before it is live is re-sent under a fresh nonce.
        msgs = _drain(ctx, result_url, seconds=8)
        if msgs:
            return msgs
        refused = _drain(ctx, dlq_url, seconds=1)
        other = [
            m for m in refused
            if json.loads(m["Body"]).get("detail", {}).get("nonce") != released
            or m.get("MessageAttributes", {}).get("ERROR_CODE", {}).get("StringValue")
            != "NO_PERMISSIONS"
        ]
        assert other == [], (
            f"the DLQ received {[m['Body'][:100] for m in other]!r} after the grant was added, "
            f"expected only a NO_PERMISSIONS copy of {released!r} while the grant propagates"
        )
        if refused:
            _release()
        return msgs

    _release()
    ran = _poll_until(
        _delivered_or_resend,
        lambda msgs: len(msgs) >= 1,
        timeout_s=240,
        interval_s=0,
        description=(
            f"with the invoke grant in place, the identical rule/target wiring delivered {released!r} "
            f"to {fn_name}, which wrote it to {result_url}"
        ),
    )
    ran_nonces = sorted(json.loads(m["Body"])["nonce"] for m in ran)
    assert ran_nonces == [released], (
        f"the repaired target processed {ran_nonces!r}, expected exactly [{released!r}] — the "
        f"dead-lettered event must not be replayed once the grant appears"
    )
    after_repair = _drain(ctx, dlq_url, seconds=max(latency, 10.0))
    assert after_repair == [], (
        f"the DLQ received {len(after_repair)} further copy/copies after the grant was added "
        f"({[m['Body'][:100] for m in after_repair]!r}), expected none — the repair must make the "
        f"identical call succeed rather than dead-letter again"
    )


def _get_policy_or_none(lam, fn_name):
    """Preflight probe: a function with no resource policy answers ResourceNotFoundException,
    which is the state this check requires."""
    try:
        return lam.get_policy(FunctionName=fn_name)["Policy"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return None
        raise


def _create_function(ctx, lam, name, role_arn, result_queue_url, check_tag):
    def _create():
        return lam.create_function(
            FunctionName=name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": _zip_bytes(_FN_SRC)},
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
    """Poll probe only — never used inside an assert."""
    try:
        return fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("InvalidParameterValueException", "AccessDeniedException"):
            return code
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
