"""throttled-lambda-target-is-one-successful-attempt-with-no-retry-and-no-dlq."""

from __future__ import annotations

import io
import json
import time
import uuid
import zipfile
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "throttled-lambda-target-is-one-successful-attempt-with-no-retry-and-no-dlq"
GROUP = "event-propagation"
SERVICES = ["events", "sqs"]

_SOURCE = "sim2real.nd.retrycount"
_DETAIL_TYPE = "RetryCountProbe"

_FN_SRC = """
import json, os, boto3
def handler(event, context):
    boto3.client("sqs").send_message(
        QueueUrl=os.environ["RESULT_QUEUE_URL"],
        MessageBody=json.dumps({"nonce": event.get("detail", {}).get("nonce"),
                                "request_id": context.aws_request_id}),
    )
    return {"ok": True}
"""


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    """A bounded retry that RAISES on its deadline. Never returns its last value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _error(fn):
    """The AWS error (code, message) raised by fn(). RAISES if fn() unexpectedly SUCCEEDS."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError("the call was expected to be rejected but it succeeded")


def _zip_bytes(src, name="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo(name)
        info.external_attr = 0o755 << 16
        zf.writestr(info, src)
    return buf.getvalue()


def _make_queue(ctx, name, *, service_principal, source_arn_like, check_tag):
    """Create an SQS queue whose policy lets one AWS service send to it. Returns (url, arn)."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=name, tags={"sim2real-check": check_tag})["QueueUrl"]
    ctx.on_cleanup(lambda u=url: ctx.client("sqs").delete_queue(QueueUrl=u))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    policy = {
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
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return url, arn


def _drain(ctx, url, *, seconds):
    """Long-poll a queue for `seconds`, deleting what it sees so a later drain cannot double-count.
    `.get("Messages", [])` here feeds a LOOP and then exact-count assertions, which is the
    sanctioned polarity: an empty default is the value the absence assertions exist to detect."""
    sqs = ctx.client("sqs")
    out = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=5,
            MessageAttributeNames=["All"],
            MessageSystemAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            out.append(msg)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _queue_depth(ctx, url):
    """Every counted message, visible or not — a second, independent observable alongside an
    empty receive."""
    attrs = ctx.client("sqs").get_queue_attributes(
        QueueUrl=url,
        AttributeNames=[
            "ApproximateNumberOfMessages",
            "ApproximateNumberOfMessagesNotVisible",
            "ApproximateNumberOfMessagesDelayed",
        ],
    )["Attributes"]
    return sum(
        int(attrs[k])
        for k in (
            "ApproximateNumberOfMessages",
            "ApproximateNumberOfMessagesNotVisible",
            "ApproximateNumberOfMessagesDelayed",
        )
    )


def _metric_sum(ctx, metric, dims, *, since, namespace="AWS/Events"):
    """Sum of a metric over [since, now+2min). Returns (total, datapoint_count) so a caller can
    distinguish 'no datapoints' from 'a zero datapoint' — several AWS/Events metrics are documented
    as only emitted when non-zero, so the two are not interchangeable."""
    resp = ctx.client("cloudwatch").get_metric_statistics(
        Namespace=namespace,
        MetricName=metric,
        Dimensions=[{"Name": k, "Value": v} for k, v in sorted(dims.items())],
        StartTime=since,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=2),
        Period=60,
        Statistics=["Sum"],
    )
    points = resp.get("Datapoints", [])  # polarity: feeds a count that is itself asserted
    return sum(p["Sum"] for p in points), len(points)


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
                "Statement": [
                    {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"},
                    {
                        "Effect": "Allow",
                        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": "*",
                    },
                ],
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
    """A zero-concurrency Lambda target with MaximumRetryAttempts=2 records exactly one successful
    invocation attempt and no retry; the DLQ stays empty, the withheld event is never delivered
    late, and lifting the throttle delivers only the NEXT event."""
    events = ctx.client("events")
    lam = ctx.client("lambda")
    account = ctx.client("sts").get_caller_identity()["Account"]
    check_tag = CHECK
    suffix = uuid.uuid4().hex[:10]

    bus = ctx.unique_name("sim2real-nd-retry-bus-")
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real-check", "Value": check_tag}])
    ctx.on_cleanup(lambda: ctx.client("events").delete_event_bus(Name=bus))

    pattern = json.dumps({"source": [_SOURCE], "detail-type": [_DETAIL_TYPE]})

    # ---- the twin control: same bus, same pattern, same instant, a target that cannot fail.
    ctl_rule = ctx.unique_name("sim2real-nd-retry-ctl-")
    events.put_rule(
        Name=ctl_rule,
        EventBusName=bus,
        EventPattern=pattern,
        State="ENABLED",
        Tags=[{"Key": "sim2real-check", "Value": check_tag}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: _teardown_rule(ctx, bus, ctl_rule, ["ctl"]))
    ctl_q_url, ctl_q_arn = _make_queue(
        ctx,
        f"sim2real-nd-retry-ctl-{suffix}",
        service_principal="events.amazonaws.com",
        source_arn_like=f"arn:*:events:{ctx.region}:{account}:rule/{bus}/*",
        check_tag=check_tag,
    )
    _put_targets_ok(events, bus, ctl_rule, [{"Id": "ctl", "Arn": ctl_q_arn}])

    # ---- the subject: identical wiring, target throttled to zero concurrency.
    result_q_url, result_q_arn = _make_queue(
        ctx,
        f"sim2real-nd-retry-result-{suffix}",
        service_principal="lambda.amazonaws.com",
        source_arn_like=f"arn:*:lambda:{ctx.region}:{account}:function:*",
        check_tag=check_tag,
    )
    dlq_url, dlq_arn = _make_queue(
        ctx,
        f"sim2real-nd-retry-dlq-{suffix}",
        service_principal="events.amazonaws.com",
        source_arn_like=f"arn:*:events:{ctx.region}:{account}:rule/{bus}/*",
        check_tag=check_tag,
    )

    role_arn = _ensure_lambda_role(ctx, f"sim2real-nd-retry-role-{suffix}", check_tag)
    fn_name = ctx.unique_name("sim2real-nd-retry-fn-")
    fn_arn = _create_function(ctx, lam, fn_name, role_arn, result_q_url, check_tag)

    # The barrier is STRUCTURAL, not a wait: zero reserved concurrency means every EventBridge
    # invoke is throttled before the handler can run.
    lam.put_function_concurrency(FunctionName=fn_name, ReservedConcurrentExecutions=0)
    conc = lam.get_function_concurrency(FunctionName=fn_name)
    assert conc.get("ReservedConcurrentExecutions") == 0, (
        f"reserved concurrency did not settle at 0 for {fn_name}: "
        f"{conc.get('ReservedConcurrentExecutions')!r} — without it the target would succeed and "
        f"every retry-count assertion below would be vacuous"
    )
    # A direct ASYNC invoke (InvocationType="Event") of this same zero-concurrency function
    # SUCCEEDS, as Lambda's docs state:
    # "For asynchronous invocation, Lambda places the event in a queue and returns a success
    # response" regardless of downstream capacity. A synchronous invoke needs a free execution
    # slot immediately and is the correct way to prove the throttle is really in force.
    direct, direct_message = _error(
        lambda: ctx.client("lambda").invoke(
            FunctionName=fn_name, InvocationType="RequestResponse", Payload=b"{}"
        )
    )
    assert direct == "TooManyRequestsException", (
        f"a synchronous invoke of the zero-concurrency function returned {direct!r}, expected "
        f"'TooManyRequestsException' — the throttle is the one thing this check breaks, so it must "
        f"be shown to be in force before EventBridge is asked to hit the same function "
        f"asynchronously"
    )
    assert direct_message == "Rate Exceeded.", (
        f"the throttled synchronous invoke must report Lambda's rate refusal, got {direct_message!r}"
    )

    subj_rule = ctx.unique_name("sim2real-nd-retry-subj-")
    subj_arn = events.put_rule(
        Name=subj_rule,
        EventBusName=bus,
        EventPattern=pattern,
        State="ENABLED",
        Tags=[{"Key": "sim2real-check", "Value": check_tag}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: _teardown_rule(ctx, bus, subj_rule, ["subj"]))
    lam.add_permission(
        FunctionName=fn_name,
        StatementId="sim2real-events",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=subj_arn,
    )
    # The grant is PRESENT on purpose: EventBridge sends missing-permission failures straight to the
    # DLQ with NO retries, which would make the retry count unobservable.
    _put_targets_ok(
        events,
        bus,
        subj_rule,
        [
            {
                "Id": "subj",
                "Arn": fn_arn,
                "RetryPolicy": {"MaximumRetryAttempts": 2, "MaximumEventAgeInSeconds": 86400},
                "DeadLetterConfig": {"Arn": dlq_arn},
            }
        ],
    )
    stored = _target_of(events, bus, subj_rule, "subj")
    assert stored["RetryPolicy"]["MaximumRetryAttempts"] == 2, (
        f"PutTargets stored MaximumRetryAttempts="
        f"{stored['RetryPolicy'].get('MaximumRetryAttempts')!r}, expected 2 — a target that silently "
        f"clamped it to 0 would produce one attempt and look like a correct retry policy"
    )

    window_start = datetime.now(timezone.utc) - timedelta(minutes=1)
    withheld = f"withheld-{uuid.uuid4().hex[:12]}"

    t0 = time.monotonic()
    resp = events.put_events(
        Entries=[
            {
                "EventBusName": bus,
                "Source": _SOURCE,
                "DetailType": _DETAIL_TYPE,
                "Detail": json.dumps({"nonce": withheld}),
            }
        ]
    )
    assert resp.get("FailedEntryCount") == 0, (
        f"PutEvents did not accept the event, so nothing below is attributable: {resp!r}"
    )

    # Beat 1 — the control proves the bus, the pattern and the fan-out all work RIGHT NOW, and
    # measures L, the latency the absence window is calibrated against.
    ctl_msgs = _poll_until(
        lambda: _drain(ctx, ctl_q_url, seconds=6),
        lambda msgs: any(withheld in m["Body"] for m in msgs),
        timeout_s=120,
        interval_s=0,
        description=(
            f"the control rule {ctl_rule} delivered {withheld!r} to {ctl_q_url} — the positive leg "
            f"of this negative-delivery check"
        ),
    )
    latency = max(time.monotonic() - t0, 1.0)
    assert any(withheld in m["Body"] for m in ctl_msgs), (
        f"the control queue never carried {withheld!r}: {[m['Body'][:120] for m in ctl_msgs]!r}"
    )

    # Beat 2 — count the attempts on an independent side channel. Lambda's invocation docs are
    # explicit that an async ("Event") invoke is accepted UNCONDITIONALLY — "Lambda places the
    # event in a queue and returns a success response" regardless of downstream capacity — and the
    # EventBridge target catalog lists "Lambda function (ASYNC)". A synchronous invoke of this same
    # zero-concurrency function throttles immediately (asserted above), but nothing about that
    # throttle is visible to a caller using the async invocation type EventBridge itself uses. So
    # EventBridge's Invoke call to this target always succeeds at the API boundary, EventBridge
    # records one successful attempt, and MaximumRetryAttempts is never consulted; no DLQ message
    # is sent, which this beat asserts on the independent metrics channel.
    def _sum(metric):
        return _metric_sum(
            ctx,
            metric,
            {"EventBusName": bus, "RuleName": subj_rule},
            since=window_start,
        )

    attempts, attempt_points = _poll_until(
        lambda: _sum("InvocationAttempts"),
        lambda pair: pair[0] >= 1,
        timeout_s=300,
        interval_s=15,
        description=(
            f"AWS/Events InvocationAttempts for rule {subj_rule} on bus {bus} recorded the single "
            f"accepted async invoke"
        ),
    )
    assert attempts == 1, (
        f"InvocationAttempts Sum={attempts} over {attempt_points} datapoint(s) for rule {subj_rule}, "
        f"expected exactly 1 — a Lambda target's async Invoke call is accepted regardless of "
        f"reserved concurrency, so EventBridge should see ONE delivery, not a retry sequence"
    )
    good, good_points = _sum("SuccessfulInvocationAttempts")
    assert good == 1, (
        f"SuccessfulInvocationAttempts Sum={good} over {good_points} datapoint(s) for rule "
        f"{subj_rule}, expected 1 — EventBridge classifies the accepted-but-unexecutable async "
        f"invoke as a SUCCESS, since Lambda's Invoke API never told it otherwise"
    )
    retries, retry_points = _sum("RetryInvocationAttempts")
    assert retries == 0, (
        f"RetryInvocationAttempts Sum={retries} over {retry_points} datapoint(s) for rule "
        f"{subj_rule}, expected 0 — MaximumRetryAttempts=2 is never consulted because EventBridge "
        f"never saw a failed attempt to retry against"
    )
    ctl_good, _ = _poll_until(
        lambda: _metric_sum(
            ctx,
            "SuccessfulInvocationAttempts",
            {"EventBusName": bus, "RuleName": ctl_rule},
            since=window_start,
        ),
        lambda pair: pair[0] >= 1,
        timeout_s=120,
        interval_s=15,
        description=(
            f"AWS/Events SuccessfulInvocationAttempts for the CONTROL rule {ctl_rule} on bus {bus} "
            f"recorded at least one success — CloudWatch's own publish latency, not just the "
            f"subject's, needs a bounded retry rather than a single read"
        ),
    )
    assert ctl_good >= 1, (
        f"SuccessfulInvocationAttempts Sum={ctl_good} for the CONTROL rule {ctl_rule}, expected >=1 "
        f"— without it, the subject's SuccessfulInvocationAttempts==1 is indistinguishable from "
        f"'this target emits no AWS/Events metrics at all'"
    )

    # Beat 3 — the DLQ never receives anything for this failure mode: EventBridge's own DLQ
    # mechanism only engages when EventBridge itself perceives a failed delivery (Beat 2's metrics
    # are the positive evidence for WHY: SuccessfulInvocationAttempts==1 already explains an empty
    # DLQ here, so this is not an unfalsifiable "nothing happened" absence).
    hold = max(3 * latency, 30.0)
    late = _drain(ctx, dlq_url, seconds=hold)
    assert late == [], (
        f"the DLQ carried {len(late)} message(s) during a {hold:.0f}s hold even though EventBridge "
        f"recorded the async invoke as successful: {[m['Body'][:120] for m in late]!r} — either the "
        f"metrics in Beat 2 or this absence is wrong, and they cannot both be right"
    )
    assert _queue_depth(ctx, dlq_url) == 0, (
        f"the DLQ reports depth {_queue_depth(ctx, dlq_url)} after an empty receive — the second "
        f"independent observable disagrees with the first"
    )
    for spelling in ("InvocationsSentToDlq", "InvocationsSentToDLQ"):
        sent, _ = _metric_sum(ctx, spelling, {"RuleName": subj_rule}, since=window_start)
        assert sent == 0, (
            f"{spelling} Sum={sent} for rule {subj_rule}, expected 0 — no dead-letter delivery "
            f"should have been recorded under either documented spelling"
        )

    # Beat 4 — freeze check, aimed at the real mechanism: while concurrency stays at
    # 0, the function must never actually run (it structurally cannot), and the attempt count
    # already recorded in Beat 2 must not silently grow later.
    stuck = _drain(ctx, result_q_url, seconds=hold)
    assert stuck == [], (
        f"the throttled function ran anyway and wrote {len(stuck)} message(s) to the result queue "
        f"during a {hold:.0f}s hold: {[m['Body'][:120] for m in stuck]!r}"
    )
    assert _queue_depth(ctx, result_q_url) == 0, (
        f"the result queue reports depth {_queue_depth(ctx, result_q_url)} after an empty receive — "
        f"the second independent observable disagrees with the first"
    )
    frozen, _ = _sum("InvocationAttempts")
    assert frozen == 1, (
        f"InvocationAttempts moved from 1 to {frozen} for rule {subj_rule} during a {hold:.0f}s "
        f"hold — nothing should re-invoke a target EventBridge already considers delivered"
    )

    # Beat 5/6 — lift the ONE broken thing (reserved concurrency) and settle what happened to the
    # withheld invocation. It does NOT survive to be flushed later. Lambda's OWN async retry
    # (fixed at 2 attempts, entirely independent of EventBridge's RetryPolicy — see Beat 2, where EventBridge itself never retried at all)
    # exhausted while concurrency was still 0 during the holds above, and this check configures
    # no on-failure destination on the function's own async invoke config, so the exhausted
    # invocation is dropped, not queued indefinitely. The withheld event is therefore never
    # delivered later, because Lambda's async retry-and-drop discarded it, not because
    # EventBridge's MaximumRetryAttempts=2 was honoured.
    lam.delete_function_concurrency(FunctionName=fn_name)
    _poll_until(
        lambda: lam.get_function_concurrency(FunctionName=fn_name).get(
            "ReservedConcurrentExecutions"
        ),
        lambda v: v is None,
        timeout_s=60,
        interval_s=3,
        description=f"reserved concurrency setting cleared for {fn_name}",
    )
    released = f"released-{uuid.uuid4().hex[:12]}"
    after = events.put_events(
        Entries=[
            {
                "EventBusName": bus,
                "Source": _SOURCE,
                "DetailType": _DETAIL_TYPE,
                "Detail": json.dumps({"nonce": released}),
            }
        ]
    )
    assert after.get("FailedEntryCount") == 0, f"the restore-leg PutEvents was refused: {after!r}"
    # Split into two independent polls so a failure localises: does the FRESH event deliver at
    # all (a basic health check on the now-unthrottled wiring, unrelated to the hypothesis under
    # test), and separately, does the WITHHELD event that Lambda's own async queue held onto
    # ever get flushed once capacity is available.
    # An async invoke Lambda still throttles while the cleared setting propagates is retried by
    # Lambda with backoff of up to 5 minutes, so the fresh event can land past 300 s.
    left = ctx.time_left()
    fresh = _poll_until(
        lambda: _drain(ctx, result_q_url, seconds=8),
        lambda msgs: any(released in m["Body"] for m in msgs),
        timeout_s=600 if left is None else max(300.0, min(600.0, left - hold - 60.0)),
        interval_s=0,
        description=(
            f"with reserved concurrency cleared, the freshly published {released!r} event reached "
            f"the function, which wrote it to {result_q_url}"
        ),
    )
    assert any(released in m["Body"] for m in fresh), (
        f"the result queue never carried {released!r} after concurrency was cleared: "
        f"{[m['Body'][:120] for m in fresh]!r} — the wiring itself is broken independent of the "
        f"withheld-event hypothesis below"
    )
    late = _drain(ctx, result_q_url, seconds=hold)
    assert not any(withheld in m["Body"] for m in late), (
        f"the withheld invocation surfaced {withheld!r} during a {hold:.0f}s hold after "
        f"concurrency was cleared: {[m['Body'][:120] for m in late]!r} — Lambda's own async retry "
        f"was expected to have exhausted and dropped it while concurrency was still 0, not to "
        f"deliver it late once capacity returned"
    )
    assert _queue_depth(ctx, result_q_url) == 0, (
        f"the result queue reports depth {_queue_depth(ctx, result_q_url)} after an empty receive "
        f"— the second independent observable disagrees with the first"
    )


def _create_function(ctx, lam, name, role_arn, result_queue_url, check_tag):
    """Create the target, retrying only IAM role propagation."""
    def _create():
        ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
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
    """Returns the response dict, or the error code string while the role is still propagating.
    Only ever used as a POLL probe, never inside an assert."""
    try:
        return fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("InvalidParameterValueException", "AccessDeniedException"):
            return code
        raise


def _put_targets_ok(events, bus, rule, targets):
    resp = events.put_targets(Rule=rule, EventBusName=bus, Targets=targets)
    assert resp.get("FailedEntryCount") == 0, (
        f"put_targets on {rule} reported failures, so the wiring under test does not exist: "
        f"{resp.get('FailedEntries')!r}"
    )


def _target_of(events, bus, rule, target_id):
    listed = events.list_targets_by_rule(Rule=rule, EventBusName=bus)["Targets"]
    for target in listed:
        if target["Id"] == target_id:
            return target
    raise AssertionError(
        f"target {target_id!r} is absent from ListTargetsByRule for {rule}: "
        f"{[t['Id'] for t in listed]!r}"
    )


def _teardown_rule(ctx, bus, rule, target_ids):
    events = ctx.client("events")
    events.remove_targets(Rule=rule, EventBusName=bus, Ids=target_ids, Force=True)
    events.delete_rule(Name=rule, EventBusName=bus, Force=True)


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
