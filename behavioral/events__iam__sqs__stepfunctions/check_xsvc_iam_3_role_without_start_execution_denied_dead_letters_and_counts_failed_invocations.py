"""xsvc-iam-3-role-without-start-execution-denied-dead-letters-and-counts-failed-invocations."""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-iam-3-role-without-start-execution-denied-dead-letters-and-counts-failed-invocations"
GROUP = "permission-chain"
SERVICES = ["events", "iam", "stepfunctions", "sqs"]

_DETAIL_TYPE = "Sim2realOrderPlaced"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


# How long one repaired-rule event is watched for an execution before another is fired.
_REFIRE_WATCH_S = 15.0


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition", ctx=None):
    """A bounded wait that RAISES on its deadline; never returns its last value on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() + interval_s > deadline:
            break
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s:.0f}s. Last result: {last!r}")


def _delete_role(iam, name):
    for pol in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=name, PolicyName=pol)
    iam.delete_role(RoleName=name)


def _trust(service):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}
            ],
        }
    )


def _create_role(ctx, name, trusted_service, statements):
    iam = ctx.client("iam")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_trust(trusted_service),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx.client("iam"), name))
    if statements:
        iam.put_role_policy(
            RoleName=name,
            PolicyName="sim2real-inline",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
    return arn


def _create_state_machine(ctx, name, role_arn, definition):
    sfn = ctx.client("stepfunctions")

    def _attempt():
        try:
            return sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
        except ClientError as exc:
            # A just-created execution role is not yet assumable by states.amazonaws.com.
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                return None
            raise

    # IAM propagation exposes no pollable condition: the create is retried on AccessDenied only.
    arn = _poll_until(
        _attempt,
        lambda a: a is not None,
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=2,
        description=f"create_state_machine {name} accepted its execution role (IAM propagation)",
        ctx=ctx,
    )
    ctx.on_cleanup(lambda: ctx.client("stepfunctions").delete_state_machine(stateMachineArn=arn))
    return arn


def _create_dlq(ctx, name, bus_rule_arn_like):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: ctx.client("sqs").delete_queue(QueueUrl=url))
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
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": arn,
                            "Condition": {"ArnLike": {"aws:SourceArn": bus_rule_arn_like}},
                        }
                    ],
                }
            )
        },
    )
    return url, arn


def _drain(ctx, url, *, seconds, wait_s=2):
    sqs = ctx.client("sqs")
    out = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s,
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            out.append(msg)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _execution_inputs(ctx, sm_arn):
    sfn = ctx.client("stepfunctions")
    out = []
    for page in sfn.get_paginator("list_executions").paginate(stateMachineArn=sm_arn):
        for ex in page["executions"]:
            d = sfn.describe_execution(executionArn=ex["executionArn"])
            out.append((d, json.loads(d["input"])))
    return out


def _execution_nonces(ctx, sm_arn):
    return [body["detail"]["nonce"] for _, body in _execution_inputs(ctx, sm_arn)]


def _attr(msg, key):
    return msg.get("MessageAttributes", {}).get(key, {}).get("StringValue")


def _make_rule(ctx, bus, name, pattern, target):
    events = ctx.client("events")
    arn = events.put_rule(
        Name=name,
        EventBusName=bus,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: ctx.client("events").delete_rule(Name=name, EventBusName=bus))
    put = events.put_targets(Rule=name, EventBusName=bus, Targets=[target])
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(
            Rule=name, EventBusName=bus, Ids=[target["Id"]], Force=True
        )
    )
    assert put["FailedEntryCount"] == 0, (
        f"PutTargets on {name} reported FailedEntryCount={put['FailedEntryCount']}: "
        f"{put['FailedEntries']!r} — real AWS accepts this target; the role is only evaluated at "
        f"delivery"
    )
    return arn


def _fire(ctx, bus, source, nonce, extra_entries=()):
    resp = ctx.client("events").put_events(
        Entries=[
            {
                "EventBusName": bus,
                "Source": source,
                "DetailType": _DETAIL_TYPE,
                "Detail": json.dumps({"nonce": nonce}),
            },
            *extra_entries,
        ]
    )
    assert resp["FailedEntryCount"] == 0, f"PutEvents refused an entry: {resp['Entries']!r}"
    return resp["Entries"][0]["EventId"]


def _deliver_round(ctx, bus, source, dlq_url, legs, *, extra_entries=()):
    """Fire ONE event that every leg's rule matches, then wait until EVERY leg resolved: its state
    machine started an execution for this nonce, or its rule dead-lettered this nonce. `legs` maps
    rule ARN -> state machine ARN. Returns (nonce, event_id, {rule_arn: dlq_msg}, strays)."""
    nonce = uuid.uuid4().hex
    event_id = _fire(ctx, bus, source, nonce, extra_entries)
    dead, strays = {}, []

    def _probe():
        for m in _drain(ctx, dlq_url, seconds=1, wait_s=1):
            body = json.loads(m["Body"])
            rule = _attr(m, "RULE_ARN")
            if body.get("detail", {}).get("nonce") == nonce and rule in legs and rule not in dead:
                dead[rule] = m
            else:
                strays.append(m)
        started = {r for r, sm in legs.items() if r not in dead and nonce in _execution_nonces(ctx, sm)}
        return set(dead) | started

    _poll_until(
        _probe,
        lambda resolved: resolved == set(legs),
        timeout_s=_budget_s(ctx, 180.0),
        interval_s=1,
        description=f"every rule resolved event {nonce!r} (execution started or dead-lettered)",
        ctx=ctx,
    )
    return nonce, event_id, dead, strays

_PASS = {"StartAt": "Done", "States": {"Done": {"Type": "Pass", "End": True}}}


def _differential_rounds(ctx, bus, source, dlq_url, good, bad, *, expected_bad_code, timeout_s):
    """Fire one event per round at the healthy and broken (rule_arn, sm_arn) legs until the broken
    leg dead-letters `expected_bad_code` while the healthy leg executes in the same round.
    Only FAILED_TO_ASSUME_ROLE (new-role trust not yet propagated to STS) re-fires a round, until
    the timeout_s deadline."""
    rounds, good_ran, good_dead = [], [], 0
    deadline = time.monotonic() + timeout_s
    while not rounds or time.monotonic() < deadline:
        nonce, event_id, dead, strays = _deliver_round(
            ctx, bus, source, dlq_url, {good[0]: good[1], bad[0]: bad[1]}
        )
        rounds.append(nonce)
        assert strays == [], (
            f"the DLQ held copies this round did not produce: "
            f"{[(_attr(m, 'RULE_ARN'), _attr(m, 'ERROR_CODE')) for m in strays]!r}"
        )
        assert bad[0] in dead, (
            f"the broken rule {bad[0]} STARTED an execution of {bad[1]} for {nonce!r}; it must be "
            f"refused at delivery"
        )
        if good[0] in dead:
            code = _attr(dead[good[0]], "ERROR_CODE")
            assert code == "FAILED_TO_ASSUME_ROLE", (
                f"the healthy rule {good[0]} was dead-lettered with ERROR_CODE={code!r}: "
                f"{_attr(dead[good[0]], 'ERROR_MESSAGE')!r}"
            )
            good_dead += 1
            continue
        good_ran.append(nonce)
        code = _attr(dead[bad[0]], "ERROR_CODE")
        if code == expected_bad_code:
            return rounds, dead[bad[0]], event_id, nonce, good_ran, good_dead
        assert code == "FAILED_TO_ASSUME_ROLE", (
            f"DLQ ERROR_CODE={code!r} for the broken rule, expected {expected_bad_code!r}. "
            f"ERROR_MESSAGE={_attr(dead[bad[0]], 'ERROR_MESSAGE')!r}"
        )
    if _budget_spent(ctx):
        raise TimeoutError(
            f"the broken leg dead-lettered with {expected_bad_code!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"{len(rounds)} rounds in {timeout_s:.0f}s never showed the healthy leg executing beside "
        f"the broken leg dead-lettered with {expected_bad_code!r} (healthy leg dead-lettered {good_dead} time(s))"
    )


def _repair_and_refire(ctx, bus, source, bad_sm, *, description):
    repaired = []

    def _refire_and_look():
        repaired.append(uuid.uuid4().hex)
        _fire(ctx, bus, source, repaired[-1])
        watch_until = time.monotonic() + _budget_s(ctx, _REFIRE_WATCH_S)
        while True:
            ran = _execution_nonces(ctx, bad_sm)
            if ran or time.monotonic() >= watch_until:
                return ran
            time.sleep(1)

    ran = _poll_until(
        _refire_and_look, lambda ns: len(ns) >= 1, timeout_s=_budget_s(ctx, 180.0), interval_s=0,
        description=description, ctx=ctx,
    )
    return ran, repaired


def _metric_sum(ctx, metric, bus, rule, since):
    resp = ctx.client("cloudwatch").get_metric_statistics(
        Namespace="AWS/Events",
        MetricName=metric,
        Dimensions=[{"Name": "EventBusName", "Value": bus}, {"Name": "RuleName", "Value": rule}],
        StartTime=since,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=2),
        Period=60,
        Statistics=["Sum"],
    )
    return sum(p["Sum"] for p in resp["Datapoints"])


# timing:real-time — metric: 45 s https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-monitoring.html
@tags(
    "axis:rejection",
    "cap:c7",
    "concern:e2e",
    "concern:eventing",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A trusted target role lacking states:StartExecution starts nothing, dead-letters
    NO_PERMISSIONS and counts in FailedInvocations for that rule only; granting it makes delivery
    work.
    """
    events = ctx.client("events")
    ident = ctx.client("sts").get_caller_identity()
    account = ident["Account"]
    partition = ident["Arn"].split(":")[1]
    suffix = uuid.uuid4().hex[:10]
    source = f"sim2real.xsvc.iam3.{suffix}"
    pattern = {"source": [source], "detail-type": [_DETAIL_TYPE]}
    sm_prefix = f"arn:{partition}:states:{ctx.region}:{account}:stateMachine:"
    good_sm_name = f"sim2real-xsvc-iam3-good-{suffix}"
    bad_sm_name = f"sim2real-xsvc-iam3-bad-{suffix}"

    # Roles first, so they have propagated by the time the first event is delivered.
    good_role = _create_role(
        ctx,
        f"sim2real-xsvc-iam3-goodr-{suffix}",
        "events.amazonaws.com",
        [{"Effect": "Allow", "Action": "states:StartExecution", "Resource": sm_prefix + good_sm_name}],
    )
    # The ONE broken thing: trusted by events.amazonaws.com, but its only grant on the target
    # state machine is a near-miss action — no states:StartExecution.
    bad_role_name = f"sim2real-xsvc-iam3-badr-{suffix}"
    bad_role = _create_role(
        ctx,
        bad_role_name,
        "events.amazonaws.com",
        [{"Effect": "Allow", "Action": "states:DescribeStateMachine", "Resource": sm_prefix + bad_sm_name}],
    )
    sm_role = _create_role(ctx, f"sim2real-xsvc-iam3-smr-{suffix}", "states.amazonaws.com", [])
    good_sm = _create_state_machine(ctx, good_sm_name, sm_role, _PASS)
    bad_sm = _create_state_machine(ctx, bad_sm_name, sm_role, _PASS)
    assert (good_sm, bad_sm) == (sm_prefix + good_sm_name, sm_prefix + bad_sm_name), (
        f"state machine ARNs {good_sm!r}, {bad_sm!r} differ from the ones the roles grant on"
    )

    bus = ctx.unique_name("sim2real-xsvc-iam3-bus-")
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ctx.client("events").delete_event_bus(Name=bus))
    dlq_url, dlq_arn = _create_dlq(
        ctx,
        f"sim2real-xsvc-iam3-dlq-{suffix}",
        f"arn:{partition}:events:{ctx.region}:{account}:rule/{bus}/*",
    )
    target = {
        "Id": "sfn",
        "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
        "DeadLetterConfig": {"Arn": dlq_arn},
    }
    good_rule = ctx.unique_name("sim2real-xsvc-iam3-good-")
    good_rule_arn = _make_rule(
        ctx, bus, good_rule, pattern, {**target, "Arn": good_sm, "RoleArn": good_role}
    )
    bad_rule = ctx.unique_name("sim2real-xsvc-iam3-bad-")
    bad_rule_arn = _make_rule(
        ctx, bus, bad_rule, pattern, {**target, "Arn": bad_sm, "RoleArn": bad_role}
    )

    window_start = datetime.now(timezone.utc) - timedelta(minutes=1)
    rounds, dead, event_id, nonce, good_ran, good_dead = _differential_rounds(
        ctx,
        bus,
        source,
        dlq_url,
        (good_rule_arn, good_sm),
        (bad_rule_arn, bad_sm),
        expected_bad_code="NO_PERMISSIONS",
        timeout_s=_budget_s(ctx, 120.0),
    )
    message = _attr(dead, "ERROR_MESSAGE") or ""
    assert "states:StartExecution" in message and f"assumed-role/{bad_role_name}/" in message, (
        f"ERROR_MESSAGE does not name the refused action and the assumed-role session of "
        f"{bad_role_name}: {message!r}"
    )
    assert _attr(dead, "TARGET_ARN") == bad_sm, (
        f"DLQ TARGET_ARN={_attr(dead, 'TARGET_ARN')!r}, expected {bad_sm!r}"
    )
    body = json.loads(dead["Body"])
    assert body.get("id") == event_id and body.get("detail") == {"nonce": nonce}, (
        f"the dead-lettered body is not the envelope PutEvents minted (EventId={event_id!r}, "
        f"nonce={nonce!r}): {body!r}"
    )

    # The service's own per-rule record. Every round dead-lettered the denied rule exactly once
    # (MaximumRetryAttempts=0); the sibling failed only in the rounds we saw it dead-lettered.
    def _metrics():
        return (
            _metric_sum(ctx, "FailedInvocations", bus, bad_rule, window_start),
            _metric_sum(ctx, "Invocations", bus, good_rule, window_start),
            _metric_sum(ctx, "FailedInvocations", bus, good_rule, window_start),
        )

    # FailedInvocations under {EventBusName, RuleName} appears roughly 35-50 s after delivery.
    bad_failed, good_inv, good_failed = _poll_until(
        _metrics,
        lambda m: m[0] >= len(rounds) and m[1] >= len(good_ran) and m[2] >= good_dead,
        timeout_s=_budget_s(ctx, 300.0),
        interval_s=2,
        description=(
            f"AWS/Events FailedInvocations[{bad_rule}] >= {len(rounds)} and "
            f"Invocations[{good_rule}] >= {len(good_ran)}"
        ),
        ctx=ctx,
    )
    assert bad_failed == len(rounds), (
        f"FailedInvocations for the denied rule = {bad_failed}, expected exactly {len(rounds)} "
        f"(one per event, MaximumRetryAttempts=0)"
    )
    assert good_failed == good_dead, (
        f"FailedInvocations for the healthy sibling {good_rule} = {good_failed}, expected "
        f"{good_dead} (the rounds it was itself dead-lettered) — the denied rule's failures must "
        f"not be attributed to a sibling on the same bus"
    )

    denied_ran = _execution_nonces(ctx, bad_sm)
    assert denied_ran == [], (
        f"the denied role started {len(denied_ran)} execution(s) of {bad_sm} ({denied_ran!r}) — "
        f"a role without states:StartExecution must not start anything"
    )
    healthy = sorted(_execution_nonces(ctx, good_sm))
    assert healthy == sorted(good_ran), (
        f"the healthy state machine ran {healthy!r}, expected each delivered nonce exactly once "
        f"{sorted(good_ran)!r}"
    )
    extra = _drain(ctx, dlq_url, seconds=5)
    assert extra == [], (
        f"the DLQ received {len(extra)} further message(s): "
        f"{[(_attr(m, 'RULE_ARN'), _attr(m, 'ERROR_CODE')) for m in extra]!r}"
    )

    # REPAIR the one broken thing and demand the identical wiring now start an execution.
    ctx.client("iam").put_role_policy(
        RoleName=bad_role_name,
        PolicyName="sim2real-inline",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "states:StartExecution", "Resource": bad_sm}
                ],
            }
        ),
    )
    ran, repaired = _repair_and_refire(
        ctx, bus, source, bad_sm,
        description=f"after granting states:StartExecution, {bad_rule} started {bad_sm}",
    )
    assert set(ran) <= set(repaired), (
        f"the repaired rule ran {ran!r}; only post-repair nonces {repaired!r} may run — the "
        f"dead-lettered events must not be replayed"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
