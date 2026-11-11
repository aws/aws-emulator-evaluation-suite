"""maximum-event-age-discards-the-throttled-async-invocation-to-the-on-failure-destination."""

from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "maximum-event-age-discards-the-throttled-async-invocation-to-the-on-failure-destination"
GROUP = "error-propagation"
SERVICES = ["lambda", "sqs"]

_OCCUPY_SECONDS = 70  # strictly greater than the 60s minimum event age, so the second invoke ages out
_SHORT_AGE = 60  # the legal minimum
_LONG_AGE = 21600  # the legal maximum (6 hours)

_FN_SRC = """
import json, os, time, boto3
_SQS = boto3.client("sqs")

def handler(event, context):
    nonce = event["nonce"]
    _SQS.send_message(
        QueueUrl=os.environ["RAN_QUEUE_URL"],
        MessageBody=json.dumps({"nonce": nonce, "request_id": context.aws_request_id}),
    )
    time.sleep(int(os.environ["OCCUPY_SECONDS"]))
    return {"nonce": nonce}
"""


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


def _make_queue(ctx, name, check_tag):
    """A plain queue. Lambda writes to its destinations and to the side channel with the FUNCTION'S
    execution role, so no resource policy is needed."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=name, tags={"sim2real-check": check_tag})["QueueUrl"]
    ctx.on_cleanup(lambda u=url: ctx.client("sqs").delete_queue(QueueUrl=u))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return url, arn


def _drain(ctx, url, *, seconds):
    """`.get("Messages", [])` feeds a loop whose result is asserted by exact membership — the
    sanctioned polarity for an empty default."""
    sqs = ctx.client("sqs")
    out = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            out.append(json.loads(msg["Body"]))
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _assert_depth_settles_to_zero(ctx, url, what):
    """The ApproximateNumberOf* counters lag deletes (SQS GetQueueAttributes docs), so a record
    still on the queue keeps the depth above zero for the whole poll, while lag alone clears."""
    timeout_s = 90.0
    budget_s = _budget_s(ctx, timeout_s)
    start = time.monotonic()
    stop = start + min(timeout_s, budget_s)
    depth = _queue_depth(ctx, url)
    while depth != 0 and time.monotonic() < stop:
        time.sleep(5)
        depth = _queue_depth(ctx, url)
    if depth != 0 and budget_s < timeout_s:
        raise TimeoutError(
            f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
            f"{timeout_s}s depth wait ended (depth {depth}); not graded"
        )
    assert depth == 0, f"{what}: the queue {url} still reports depth {depth} behind an empty receive"


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
        PolicyName="sim2real-async",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["sqs:SendMessage", "sqs:GetQueueAttributes"],
                        "Resource": "*",
                    }
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


def _create_or_error(fn):
    """Poll probe only — never used inside an assert."""
    try:
        return fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("InvalidParameterValueException", "AccessDeniedException"):
            return code
        raise


def _create_function(ctx, name, role_arn, ran_url, check_tag):
    lam = ctx.client("lambda")

    def _create():
        return lam.create_function(
            FunctionName=name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": _zip_bytes(_FN_SRC)},
            Timeout=_OCCUPY_SECONDS + 30,
            Environment={
                "Variables": {
                    "RAN_QUEUE_URL": ran_url,
                    "OCCUPY_SECONDS": str(_OCCUPY_SECONDS),
                }
            },
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


def _configure(ctx, name, *, age, success_arn, failure_arn):
    lam = ctx.client("lambda")
    lam.put_function_event_invoke_config(
        FunctionName=name,
        MaximumRetryAttempts=2,
        MaximumEventAgeInSeconds=age,
        DestinationConfig={
            "OnSuccess": {"Destination": success_arn},
            "OnFailure": {"Destination": failure_arn},
        },
    )
    stored = lam.get_function_event_invoke_config(FunctionName=name)
    assert stored["MaximumEventAgeInSeconds"] == age, (
        f"the stored MaximumEventAgeInSeconds for {name} is "
        f"{stored.get('MaximumEventAgeInSeconds')!r}, expected {age} — the one field that differs "
        f"between the twins must actually differ"
    )
    assert stored["MaximumRetryAttempts"] == 2, (
        f"the stored MaximumRetryAttempts for {name} is {stored.get('MaximumRetryAttempts')!r}, "
        f"expected 2 — it is deliberately IDENTICAL on both twins, so it cannot explain any "
        f"difference between them"
    )
    assert stored["DestinationConfig"]["OnFailure"]["Destination"] == failure_arn, (
        f"the stored OnFailure destination for {name} is "
        f"{stored['DestinationConfig']['OnFailure'].get('Destination')!r}, expected {failure_arn!r}"
    )


# ===== the check =====
# timing:real-time — ttl: 60 s https://docs.aws.amazon.com/lambda/latest/dg/invocation-async-error-handling.html
@tags(
    "axis:negative-delivery",
    "cap:c4",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A throttled async invocation is discarded at MaximumEventAgeInSeconds and never reaches the
    handler, while an identical twin with a longer age (and the short twin once widened) discards
    neither throttled event; MaximumRetryAttempts is equal on both and cannot explain it."""
    lam = ctx.client("lambda")
    check_tag = CHECK
    suffix = uuid.uuid4().hex[:10]

    short_ran_url, _ = _make_queue(ctx, f"sim2real-nd-age-ran-s-{suffix}", check_tag)
    long_ran_url, _ = _make_queue(ctx, f"sim2real-nd-age-ran-l-{suffix}", check_tag)
    short_ok_url, short_ok_arn = _make_queue(ctx, f"sim2real-nd-age-ok-s-{suffix}", check_tag)
    short_fail_url, short_fail_arn = _make_queue(ctx, f"sim2real-nd-age-fail-s-{suffix}", check_tag)
    long_ok_url, long_ok_arn = _make_queue(ctx, f"sim2real-nd-age-ok-l-{suffix}", check_tag)
    long_fail_url, long_fail_arn = _make_queue(ctx, f"sim2real-nd-age-fail-l-{suffix}", check_tag)

    role_arn = _ensure_lambda_role(ctx, f"sim2real-nd-age-role-{suffix}", check_tag)
    short_fn = ctx.unique_name("sim2real-nd-age-short-")
    long_fn = ctx.unique_name("sim2real-nd-age-long-")
    _create_function(ctx, short_fn, role_arn, short_ran_url, check_tag)
    _create_function(ctx, long_fn, role_arn, long_ran_url, check_tag)
    _configure(ctx, short_fn, age=_SHORT_AGE, success_arn=short_ok_arn, failure_arn=short_fail_arn)
    _configure(ctx, long_fn, age=_LONG_AGE, success_arn=long_ok_arn, failure_arn=long_fail_arn)

    # The STRUCTURAL barrier, set identically on both twins: one concurrency slot, and a handler that
    # holds it for longer than the short twin's whole event age. Deliberately 1 and not 0 — zero
    # reserved concurrency is documented as "no retry", which would take the age out of play.
    for name in (short_fn, long_fn):
        lam.put_function_concurrency(FunctionName=name, ReservedConcurrentExecutions=1)
        got = lam.get_function_concurrency(FunctionName=name)["ReservedConcurrentExecutions"]
        assert got == 1, (
            f"reserved concurrency for {name} settled at {got!r}, expected 1 — without exactly one "
            f"slot the second invoke is not throttled and nothing ages out"
        )

    first = f"first-{uuid.uuid4().hex[:10]}"
    second = f"second-{uuid.uuid4().hex[:10]}"

    def _fire(name):
        for nonce in (first, second):
            resp = lam.invoke(
                FunctionName=name,
                InvocationType="Event",
                Payload=json.dumps({"nonce": nonce}).encode(),
            )
            assert resp["StatusCode"] == 202, (
                f"the async invoke of {name} with {nonce!r} answered StatusCode="
                f"{resp['StatusCode']!r}, expected 202 — a rejected invoke is a different negative"
            )

    # One burst per twin, back to back, so both see the same shape of contention.
    t_fire = time.monotonic()
    _fire(short_fn)
    _fire(long_fn)

    # BEAT 1 — the positive control on the SHORT twin's own wiring: the first invocation runs and its
    # OnSuccess destination fires. Without it, an empty OnSuccess queue would be indistinguishable
    # from a function that never runs anything.
    short_ok = _poll_until(
        lambda: _drain(ctx, short_ok_url, seconds=8),
        lambda recs: len(recs) >= 1,
        timeout_s=300,
        interval_s=0,
        description=(
            f"the short-age function {short_fn} ran its first invocation and its OnSuccess "
            f"destination {short_ok_url} received the record — the positive leg of this "
            f"negative-delivery check"
        ),
    )
    assert len(short_ok) == 1, (
        f"the short twin's OnSuccess destination received {len(short_ok)} record(s), expected exactly "
        f"1: only one of the two invocations can hold the single concurrency slot in time. Records: "
        f"{[r.get('requestPayload') for r in short_ok]!r}"
    )
    ran_short = [r["nonce"] for r in _drain(ctx, short_ran_url, seconds=8)]
    assert len(ran_short) == 1, (
        f"the short twin's handler side channel recorded {ran_short!r}, expected exactly one entry — "
        f"this is the B4 count of how many invocations actually REACHED the code"
    )
    survivor = ran_short[0]
    assert survivor in (first, second), (
        f"the short twin ran a nonce this check never sent: {survivor!r}"
    )
    succeeded = short_ok[0]["requestPayload"]["nonce"]
    assert succeeded == survivor, (
        f"the OnSuccess record names {succeeded!r} but the handler side channel recorded "
        f"{survivor!r} — the destination record must describe the invocation that ran"
    )

    # BEAT 2 — the discard. The other nonce aged out and must land on OnFailure.
    short_fail = _poll_until(
        lambda: _drain(ctx, short_fail_url, seconds=8),
        lambda recs: len(recs) >= 1,
        timeout_s=300,
        interval_s=0,
        description=(
            f"the short-age function {short_fn} discarded its throttled second invocation to the "
            f"OnFailure destination {short_fail_url} once the event exceeded "
            f"MaximumEventAgeInSeconds={_SHORT_AGE}"
        ),
    )
    assert len(short_fail) == 1, (
        f"the short twin's OnFailure destination received {len(short_fail)} record(s), expected "
        f"exactly 1: {[r.get('requestContext', {}).get('condition') for r in short_fail]!r}"
    )
    discarded = short_fail[0]
    expected_discarded = second if survivor == first else first
    assert discarded["requestPayload"] == {"nonce": expected_discarded}, (
        f"the OnFailure record carries requestPayload={discarded.get('requestPayload')!r}, expected "
        f"{{'nonce': {expected_discarded!r}}} — the discarded event must carry the ORIGINAL payload "
        f"byte for byte, not a synthesised stub"
    )
    condition = discarded.get("requestContext", {}).get("condition")
    assert condition == "EventAgeExceeded", (
        f"the OnFailure record's requestContext.condition is {condition!r}, expected "
        f"'EventAgeExceeded'. 'RetriesExhausted' here would mean the throttle was counted against "
        f"MaximumRetryAttempts (which is 2 on BOTH twins), and the documented split between the two "
        f"overrides does not hold (H1/H3)"
    )
    assert discarded.get("requestContext", {}).get("requestId"), (
        f"the OnFailure record carries no requestContext.requestId "
        f"({sorted(discarded.get('requestContext', {}))!r}) — a live request id is the field no "
        f"recording can carry"
    )
    # The MEASURED latency from firing the burst to the short twin's own discard landing. Real AWS
    # documents that a throttled event "might wait in the queue for hours" before being retried
    # (docs.aws.amazon.com/lambda/latest/dg/invocation-retries.html). "Eventually runs" is
    # therefore not a boundable claim for either twin; the
    # discard LATENCY is, and every absence window below is calibrated against it.
    discard_latency_s = time.monotonic() - t_fire

    # BEAT 3 — THE NEGATIVE: the discarded invocation NEVER reached the handler.
    tail = [r["nonce"] for r in _drain(ctx, short_ran_url, seconds=max(_OCCUPY_SECONDS, 60))]
    assert expected_discarded not in ran_short + tail, (
        f"the aged-out nonce {expected_discarded!r} appears in the short twin's handler side channel "
        f"({ran_short + tail!r}) — a discarded event must never be delivered to the code, and the "
        f"OnFailure record above would then be describing an invocation that actually ran"
    )
    _assert_depth_settles_to_zero(
        ctx, short_fail_url,
        "the short twin's OnFailure queue holds a second discard, so 'exactly one' is not stable")

    # BEAT 4 — THE TWIN, in the same run, on the same code and the same single slot, subjected to the
    # SAME throttle: at this same point in wall-clock time — already comfortably longer than
    # `discard_latency_s`, since BEATs 1-3 on the short twin have already elapsed — the long-age
    # twin's second invocation has NOT been discarded. That is the whole discriminating claim: an
    # emulator that retries a throttle against MaximumRetryAttempts (equal on both twins) rather than
    # MaximumEventAgeInSeconds discards HERE too, on the same schedule as the short twin above.
    long_ran = _poll_until(
        lambda: [r["nonce"] for r in _drain(ctx, long_ran_url, seconds=8)],
        lambda nonces: len(nonces) >= 1,
        timeout_s=300,
        interval_s=0,
        description=(
            f"the long-age function {long_fn} ran its first invocation — the positive control on its "
            f"own wiring"
        ),
    )
    elapsed_since_fire = time.monotonic() - t_fire
    assert elapsed_since_fire >= discard_latency_s, (
        f"only {elapsed_since_fire:.1f}s have elapsed since the burst was fired, less than the "
        f"{discard_latency_s:.1f}s it took the short twin to discard above — the absence check below "
        f"would not yet be meaningful"
    )
    # How many of the two have reached the handler by now is NOT asserted: AWS's own retry timing for
    # a throttled event is not bounded (a throttled event can wait in the queue for hours) — the
    # discriminating claim is only that neither was DISCARDED, which the next assertion checks.
    assert set(long_ran) <= {first, second}, (
        f"the long twin's handler side channel recorded a nonce this check never sent: {long_ran!r}"
    )
    long_fail_mid = _drain(ctx, long_fail_url, seconds=8)
    assert long_fail_mid == [], (
        f"the long-age twin's OnFailure destination already received {len(long_fail_mid)} record(s) "
        f"after {elapsed_since_fire:.1f}s — longer than the {discard_latency_s:.1f}s that discarded "
        f"the short twin's second invocation above: "
        f"{[r.get('requestContext', {}).get('condition') for r in long_fail_mid]!r}. With "
        f"MaximumEventAgeInSeconds={_LONG_AGE} the throttled invocation must still be queued for "
        f"retry, not discarded"
    )
    _assert_depth_settles_to_zero(
        ctx, long_fail_url, "the long twin's OnFailure queue holds a discard")

    # BEAT 5/6 — restore: widen the short twin's age to match, and the discard stops happening. As
    # above, "eventually runs" is not a boundable claim once an invocation has been throttled — the
    # provable restoration is that the SAME throttle scenario that discarded `second` under a 60s age
    # does not discard `fourth` under a 21600s age, held for the SAME calibrated window (B5: ≥3x the
    # measured discard latency) that was long enough to prove the discard above.
    _configure(ctx, short_fn, age=_LONG_AGE, success_arn=short_ok_arn, failure_arn=short_fail_arn)
    third = f"third-{uuid.uuid4().hex[:10]}"
    fourth = f"fourth-{uuid.uuid4().hex[:10]}"
    t_fire_2 = time.monotonic()
    for nonce in (third, fourth):
        resp = lam.invoke(
            FunctionName=short_fn,
            InvocationType="Event",
            Payload=json.dumps({"nonce": nonce}).encode(),
        )
        assert resp["StatusCode"] == 202, (
            f"the async invoke of {short_fn} with {nonce!r} answered StatusCode="
            f"{resp['StatusCode']!r}, expected 202"
        )

    ran_after: list[str] = []

    def _collect():
        ran_after.extend(r["nonce"] for r in _drain(ctx, short_ran_url, seconds=10))
        return ran_after

    # The async event queue documents no FIFO order, so either of the two may take the slot first.
    _poll_until(
        _collect,
        lambda nonces: third in nonces or fourth in nonces,
        timeout_s=300,
        interval_s=0,
        description=(
            f"with MaximumEventAgeInSeconds widened to {_LONG_AGE}, {short_fn} ran one of its next "
            f"invocations {third!r} / {fourth!r} — the positive control on the restored wiring"
        ),
    )
    assert set(ran_after) <= {third, fourth}, (
        f"after widening the age the short twin ran {ran_after!r}, expected only {third!r} / "
        f"{fourth!r}"
    )
    hold_s = max(3 * discard_latency_s, 30.0)
    remaining_s = max(hold_s - (time.monotonic() - t_fire_2), 8.0)
    late = _drain(ctx, short_fail_url, seconds=remaining_s)  # bounded active poll, not a bare sleep
    assert late == [], (
        f"the short twin discarded {len(late)} further event(s) {hold_s:.1f}s after its age was "
        f"widened to {_LONG_AGE}: {[r.get('requestPayload') for r in late]!r} — the SAME throttle "
        f"scenario that discarded {expected_discarded!r} under a {_SHORT_AGE}s age must discard "
        f"neither {third!r} nor {fourth!r} under a {_LONG_AGE}s age"
    )
    _assert_depth_settles_to_zero(
        ctx, short_fail_url, "the short twin's OnFailure queue holds a discard after widening the age")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
