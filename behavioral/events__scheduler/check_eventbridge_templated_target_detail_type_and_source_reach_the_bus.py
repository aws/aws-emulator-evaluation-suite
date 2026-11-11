"""eventbridge-templated-target-detail-type-and-source-reach-the-bus."""
from __future__ import annotations

import datetime as dt
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-templated-target-detail-type-and-source-reach-the-bus"
GROUP = 'eventing'
SERVICES = ['events', 'scheduler']

#: Seconds between "the schedule has been created" and its nominal one-time instant. Anchored
#: after provisioning: IAM propagation can delay CreateSchedule past an instant computed before.
_FIRE_OFFSET_S = 90

#: Poll budget for the delivered event to reach the consumer queue. Not an asserted deadline.
_DELIVERY_BUDGET_S = 420.0

#: Bound on the CreateSchedule retry loop that waits out role propagation.
_CREATE_TIMEOUT_S = 180.0

_MAX_CREDIBLE_DELIVERY_WAIT_S = 120.0
#: The floor for the absence window, and its ceiling. The window actually used is
#: max(floor, 3 x the measured positive-control latency), capped by the ceiling.
_ABSENCE_FLOOR_BUDGET_S = 90.0
_ABSENCE_CEILING_BUDGET_S = 360.0

#: The two values under test. `_SOURCE` deliberately does NOT begin "aws." — the documented
#: pattern for this field excludes that prefix, which is the rejection arm below.
_SOURCE = "sim2real.scheduler-templated"
_DETAIL_TYPE = "sim2real.ScheduledFire"

#: A detail-type the schedule never emits. The twin rule asks for it, so the twin's pattern is
#: unsatisfiable BY CONSTRUCTION for as long as the schedule declares `_DETAIL_TYPE`.
_UNREACHABLE_DETAIL_TYPE = "sim2real.NeverEmitted"

_FORBIDDEN_SOURCE = "aws.sim2real-scheduler"
_FORBIDDEN_SOURCE_REFUSAL = (
    f"1 validation error detected: Value '{_FORBIDDEN_SOURCE}' at "
    "'target.eventBridgeParameters.source' failed to satisfy constraint: Member must satisfy "
    "regular expression pattern: "
    r"(?=[/\.\-_A-Za-z0-9]+)((?!aws\.).*)|(\$(\.[\w_-]+(\[(\d+|\*)\])*)*)"
)


def _receive(sqs, url: str, wait: int = 5) -> list[dict]:
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait)
    msgs = resp.get("Messages", [])
    if msgs:
        sqs.delete_message_batch(QueueUrl=url, Entries=[
            {"Id": f"d{i}", "ReceiptHandle": m["ReceiptHandle"]} for i, m in enumerate(msgs)])
    return [json.loads(m["Body"]) for m in msgs]


def _queue(sqs, ctx, region: str, account: str, bus: str) -> tuple[str, str]:
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-sched-eb-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowEventBridge", "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": arn,
            "Condition": {"ArnLike": {
                "aws:SourceArn": f"arn:aws:events:{region}:{account}:rule/{bus}/*"}},
        }],
    })})
    return url, arn


def _collect(sqs, url: str, probe: str, budget_s: float) -> list[dict]:
    """Every envelope on *url* whose detail names *probe*, within *budget_s*."""
    got: list[dict] = []
    deadline = time.monotonic() + budget_s
    while time.monotonic() < deadline and not got:
        got += [e for e in _receive(sqs, url)
                if isinstance(e.get("detail"), dict) and e["detail"].get("probe") == probe]
    return got


def _drain_empty(sqs, url: str, budget_s: float = 60.0) -> None:
    empties = 0
    deadline = time.monotonic() + budget_s
    while time.monotonic() < deadline and empties < 2:
        empties = empties + 1 if not _receive(sqs, url, wait=2) else 0
    assert empties >= 2, f"queue {url!r} would not drain to empty inside {budget_s}s"


def _scheduler_role(ctx, iam, bus_arn: str) -> str:
    """A role Scheduler can assume to put events on exactly this bus."""
    name = ctx.unique_name("sim2real-behav-sched-eb-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "scheduler.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
        Description="sim2real-behav scheduler->eventbridge templated target",
        Tags=[{"Key": "sim2real", "Value": "scheduler-eventbridge-target"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _drop_role(iam, name))
    iam.put_role_policy(
        RoleName=name, PolicyName="put-events",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "events:PutEvents", "Resource": bus_arn}],
        }),
    )
    return arn


def _drop_role(iam, name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=name, PolicyName="put-events")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=name)


def _create_schedule_with_retry(scheduler, **kwargs) -> None:
    """CreateSchedule, retrying while Scheduler cannot yet assume the new role; raise on timeout.

    Only the documented propagation refusals naming the assume-role problem are retried.
    """
    deadline = time.monotonic() + _CREATE_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        try:
            scheduler.create_schedule(**kwargs)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = exc.response.get("Error", {}).get("Message", "")
            if code in ("ResourceNotFoundException", "ValidationException") and (
                    "assume" in msg.lower() or "must allow" in msg.lower()):
                last = exc
                time.sleep(5.0)
                continue
            raise
    raise AssertionError(
        f"CreateSchedule never accepted the freshly minted role within {_CREATE_TIMEOUT_S}s; "
        f"last refusal was {last!r}"
    )


def _client_error(fn) -> tuple[str, str]:
    """Return (code, message) of the ClientError *fn* raises; raise if *fn* succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        "the call under test was expected to be refused and instead succeeded"
    )


# timing:real-time — schedule: 90 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:negative-delivery", "cap:c4", "cap:c7", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A schedule targeting a bus with EventBridgeParameters emits an event with that Source and
    DetailType (Input as detail) to a rule's queue; a twin rule for another detail-type gets nothing
    until repointed; an "aws."-prefixed Source is refused with ValidationException.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-scheduler-schedule-eventbridgeparameters.html
    """
    ev = ctx.client("events")
    sqs = ctx.client("sqs")
    scheduler = ctx.client("scheduler")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    bus = ctx.unique_name("sim2real-behav-sched-eb-")
    bus_arn = ev.create_event_bus(
        Name=bus, Tags=[{"Key": "sim2real", "Value": "scheduler-eventbridge-target"}],
    )["EventBusArn"]
    ctx.on_cleanup(lambda: ev.delete_event_bus(Name=bus))

    match_url, match_arn = _queue(sqs, ctx, ctx.region, account, bus)
    twin_url, twin_arn = _queue(sqs, ctx, ctx.region, account, bus)

    match_rule, twin_rule = f"{bus}-match", f"{bus}-twin"
    for rule, detail_type, arn in ((match_rule, _DETAIL_TYPE, match_arn),
                                   (twin_rule, _UNREACHABLE_DETAIL_TYPE, twin_arn)):
        ev.put_rule(Name=rule, EventBusName=bus, State="ENABLED",
                    EventPattern=json.dumps({"source": [_SOURCE], "detail-type": [detail_type]}))
        ctx.on_cleanup(lambda r=rule: ev.delete_rule(Name=r, EventBusName=bus))
        resp = ev.put_targets(Rule=rule, EventBusName=bus, Targets=[{"Id": "q", "Arn": arn}])
        ctx.on_cleanup(lambda r=rule: ev.remove_targets(Rule=r, EventBusName=bus, Ids=["q"]))
        assert resp["FailedEntryCount"] == 0, (
            f"put_targets for rule {rule!r} reported {resp['FailedEntryCount']} failures: "
            f"{resp.get('FailedEntries')!r}"
        )
        arns = [t["Arn"] for t in ev.list_targets_by_rule(
            Rule=rule, EventBusName=bus)["Targets"]]
        assert arns == [arn], (
            f"rule {rule!r} must target exactly {arn!r}; ListTargetsByRule reports {arns!r}"
        )

    role_arn = _scheduler_role(ctx, iam, bus_arn)

    # --- the schedule under test. The instant is anchored AFTER provisioning. ----------------
    probe = ctx.unique_name("p-")
    schedule_name = ctx.unique_name("sim2real-behav-sched-eb-")
    fire_at = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=_FIRE_OFFSET_S)
    payload = {"probe": probe, "n": 11}
    _create_schedule_with_retry(
        scheduler,
        Name=schedule_name,
        ScheduleExpression=f"at({fire_at.strftime('%Y-%m-%dT%H:%M:%S')})",
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        ActionAfterCompletion="NONE",
        Description="sim2real-behav scheduler eventbridge templated target",
        Target={
            "Arn": bus_arn,
            "RoleArn": role_arn,
            "Input": json.dumps(payload),
            "EventBridgeParameters": {"DetailType": _DETAIL_TYPE, "Source": _SOURCE},
        },
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=schedule_name))

    # The configuration really is the one under test, read back through a different operation.
    got = scheduler.get_schedule(Name=schedule_name)
    assert got["Target"]["EventBridgeParameters"] == {
        "DetailType": _DETAIL_TYPE, "Source": _SOURCE}, (
        f"GetSchedule must report the configured EventBridgeParameters "
        f"{{'DetailType': {_DETAIL_TYPE!r}, 'Source': {_SOURCE!r}}}; got "
        f"{got['Target'].get('EventBridgeParameters')!r}"
    )
    assert got["Target"]["Arn"] == bus_arn, (
        f"the target must be the bus {bus_arn!r}, GetSchedule reports {got['Target']['Arn']!r}"
    )

    # --- the terminal read, at the CONSUMER --------------------------------------------------
    nominal = time.monotonic() + max(
        0.0, (fire_at - dt.datetime.now(dt.timezone.utc)).total_seconds())
    envelopes = _collect(sqs, match_url, probe, _DELIVERY_BUDGET_S)
    delivery_latency_s = max(0.0, time.monotonic() - nominal)
    assert envelopes, (
        f"the schedule's nominal instant was {fire_at.isoformat()} and no event carrying probe "
        f"{probe!r} reached the rule's queue within {_DELIVERY_BUDGET_S}s; GetSchedule reports "
        f"state {got.get('State')!r}, so the schedule existed and the EMISSION is what is missing"
    )
    envelope = envelopes[0]
    assert envelope["source"] == _SOURCE, (
        f"expected the configured Source {_SOURCE!r} on the bus, got {envelope['source']!r}"
    )
    assert envelope["detail-type"] == _DETAIL_TYPE, (
        f"expected the configured DetailType {_DETAIL_TYPE!r}, got {envelope['detail-type']!r}"
    )
    assert envelope["detail"] == payload, (
        f"the target Input must arrive as the event detail {payload!r}, got "
        f"{envelope['detail']!r}"
    )
    assert envelope["account"] == account, (
        f"the event must be attributed to this account {account!r}, got {envelope['account']!r}"
    )
    assert envelope["region"] == ctx.region, (
        f"the event must be attributed to {ctx.region!r}, got {envelope['region']!r}"
    )

    # --- the absence, on wiring identical but for the detail-type predicate ------------------
    assert delivery_latency_s <= _MAX_CREDIBLE_DELIVERY_WAIT_S, (
        f"the positive control took {delivery_latency_s:.1f}s past the nominal instant, above "
        f"the {_MAX_CREDIBLE_DELIVERY_WAIT_S}s this check will calibrate an absence against; "
        f"refusing to report an absence rather than widening the window silently"
    )
    absence_s = min(max(_ABSENCE_FLOOR_BUDGET_S, 3.0 * delivery_latency_s),
                    _ABSENCE_CEILING_BUDGET_S)
    leaked = _collect(sqs, twin_url, probe, absence_s)
    assert leaked == [], (
        f"the twin rule asks for detail-type {_UNREACHABLE_DETAIL_TYPE!r}, which this schedule "
        f"cannot emit, yet {len(leaked)} event(s) arrived over {absence_s:.0f}s: {leaked[:1]!r}"
    )
    depth = sqs.get_queue_attributes(
        QueueUrl=twin_url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    assert depth == {"ApproximateNumberOfMessages": "0",
                     "ApproximateNumberOfMessagesNotVisible": "0"}, (
        f"the twin rule's queue reports {depth!r}, not empty"
    )

    # --- the twin's own positive control: same rule, same target, satisfiable predicate -------
    ev.put_rule(Name=twin_rule, EventBusName=bus, State="ENABLED",
                EventPattern=json.dumps({"source": [_SOURCE], "detail-type": [_DETAIL_TYPE]}))
    arns = [t["Arn"] for t in ev.list_targets_by_rule(
        Rule=twin_rule, EventBusName=bus)["Targets"]]
    assert arns == [twin_arn], (
        f"repointing the twin rule dropped its target ({arns!r}), so the control below would be "
        f"untestable"
    )
    _drain_empty(sqs, twin_url)
    second_probe = ctx.unique_name("p2-")
    second_payload = {"probe": second_probe, "n": 12}
    second_name = ctx.unique_name("sim2real-behav-sched-eb2-")
    second_fire = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=_FIRE_OFFSET_S)
    _create_schedule_with_retry(
        scheduler,
        Name=second_name,
        ScheduleExpression=f"at({second_fire.strftime('%Y-%m-%dT%H:%M:%S')})",
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        ActionAfterCompletion="NONE",
        Target={
            "Arn": bus_arn, "RoleArn": role_arn, "Input": json.dumps(second_payload),
            "EventBridgeParameters": {"DetailType": _DETAIL_TYPE, "Source": _SOURCE},
        },
    )
    ctx.on_cleanup(lambda: scheduler.delete_schedule(Name=second_name))
    control = _collect(sqs, twin_url, second_probe, _DELIVERY_BUDGET_S)
    assert control, (
        f"after the SAME twin rule and target were repointed at the emitted detail-type, no "
        f"event carrying {second_probe!r} arrived in {_DELIVERY_BUDGET_S}s — so the earlier zero "
        f"cannot be attributed to the detail-type predicate"
    )
    assert control[0]["detail-type"] == _DETAIL_TYPE, (
        f"the control event carries detail-type {control[0]['detail-type']!r}"
    )

    # --- the rejection: a Source the documented pattern excludes -----------------------------
    forbidden_name = ctx.unique_name("sim2real-behav-sched-bad-")
    refusal = _client_error(lambda: scheduler.create_schedule(
        Name=forbidden_name,
        ScheduleExpression=f"at({(dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=600)).strftime('%Y-%m-%dT%H:%M:%S')})",
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        Target={
            "Arn": bus_arn, "RoleArn": role_arn, "Input": json.dumps({"probe": "forbidden"}),
            "EventBridgeParameters": {"DetailType": _DETAIL_TYPE, "Source": _FORBIDDEN_SOURCE},
        },
    ))
    assert refusal == ("ValidationException", _FORBIDDEN_SOURCE_REFUSAL), (
        f"EventBridgeParameters.Source excludes an 'aws.' prefix by its documented pattern, so "
        f"{_FORBIDDEN_SOURCE!r} must be refused with ValidationException "
        f"{_FORBIDDEN_SOURCE_REFUSAL!r}; got {refusal!r}"
    )
    # The effect is absent: the refused schedule does not exist.
    missing = _client_error(lambda: scheduler.get_schedule(Name=forbidden_name))
    expected_missing = ("ResourceNotFoundException", f"Schedule {forbidden_name} does not exist.")
    assert missing == expected_missing, (
        f"the refused schedule {forbidden_name!r} must not exist; GetSchedule answered {missing!r}, "
        f"expected {expected_missing!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
