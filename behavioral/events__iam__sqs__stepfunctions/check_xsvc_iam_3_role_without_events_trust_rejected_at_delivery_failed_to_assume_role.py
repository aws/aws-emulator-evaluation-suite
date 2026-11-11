"""xsvc-iam-3-role-without-events-trust-rejected-at-delivery-failed-to-assume-role."""

from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-iam-3-role-without-events-trust-rejected-at-delivery-failed-to-assume-role"
GROUP = "permission-chain"
SERVICES = ["events", "iam", "stepfunctions", "sqs"]

_DETAIL_TYPE = "Sim2realOrderPlaced"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    """A bounded wait that RAISES on its deadline; never returns its last value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


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

    # IAM propagation exposes no pollable condition: retry the create until it accepts the role.
    arn = _poll_until(
        _attempt,
        lambda a: a is not None,
        timeout_s=_budget_s(ctx, 98.0),
        interval_s=2,
        description=f"create_state_machine {name} accepted its execution role (IAM propagation)",
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


def _drain(ctx, url, *, seconds):
    sqs = ctx.client("sqs")
    out = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2, MessageAttributeNames=["All"]
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
        for m in _drain(ctx, dlq_url, seconds=4):
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
        timeout_s=180,
        interval_s=2,
        description=f"every rule resolved event {nonce!r} (execution started or dead-lettered)",
    )
    return nonce, event_id, dead, strays

_PASS = {"StartAt": "Done", "States": {"Done": {"Type": "Pass", "End": True}}}


def _differential_rounds(ctx, bus, source, dlq_url, good, bad, *, expected_bad_code, max_rounds):
    """Fire one event per round at the healthy and broken (rule_arn, sm_arn) legs until the broken
    leg dead-letters `expected_bad_code` while the healthy leg executes in the same round.
    Only FAILED_TO_ASSUME_ROLE (new-role trust not yet propagated to STS) re-fires a round."""
    rounds, good_ran, good_dead = [], [], 0
    for _ in range(max_rounds):
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
    raise AssertionError(
        f"{max_rounds} rounds never showed the healthy leg executing beside the broken leg "
        f"dead-lettered with {expected_bad_code!r} (healthy leg dead-lettered {good_dead} time(s))"
    )


def _repair_and_refire(ctx, bus, source, bad_sm, *, description):
    """Poll every 2 s for an execution, re-firing every 16 s while the repaired trust propagates."""
    repaired = []
    timeout_s = _budget_s(ctx, 180.0)
    deadline = time.monotonic() + timeout_s
    polls = 0
    while True:
        if polls % 8 == 0:
            repaired.append(uuid.uuid4().hex)
            _fire(ctx, bus, source, repaired[-1])
        ran = _execution_nonces(ctx, bad_sm)
        if ran:
            return ran, repaired
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s:.0f}s")
        polls += 1
        time.sleep(2)


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:e2e",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A target role whose trust omits events.amazonaws.com is accepted by PutTargets but
    dead-letters with FAILED_TO_ASSUME_ROLE and starts nothing; fixing only the trust makes it work.
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
    # The ONE broken thing: the identity policy is correct, but the trust policy names a
    # different service principal, so events.amazonaws.com cannot assume the role.
    bad_role_name = f"sim2real-xsvc-iam3-notrust-{suffix}"
    bad_role = _create_role(
        ctx,
        bad_role_name,
        "lambda.amazonaws.com",
        [{"Effect": "Allow", "Action": "states:StartExecution", "Resource": sm_prefix + bad_sm_name}],
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
    bad_rule = ctx.unique_name("sim2real-xsvc-iam3-notrust-")
    bad_rule_arn = _make_rule(
        ctx, bus, bad_rule, pattern, {**target, "Arn": bad_sm, "RoleArn": bad_role}
    )
    # PutTargets does not validate the trust policy; the refusal only shows at delivery.
    listed = events.list_targets_by_rule(Rule=bad_rule, EventBusName=bus)["Targets"]
    assert [t.get("RoleArn") for t in listed] == [bad_role], (
        f"the accepted target does not carry the un-assumable RoleArn {bad_role!r}: {listed!r}"
    )

    rounds, dead, event_id, nonce, good_ran, _ = _differential_rounds(
        ctx,
        bus,
        source,
        dlq_url,
        (good_rule_arn, good_sm),
        (bad_rule_arn, bad_sm),
        expected_bad_code="FAILED_TO_ASSUME_ROLE",
        max_rounds=4,
    )
    message = _attr(dead, "ERROR_MESSAGE") or ""
    assert "sts:AssumeRole" in message and bad_role in message, (
        f"ERROR_MESSAGE does not name sts:AssumeRole on {bad_role!r}: {message!r}"
    )
    assert _attr(dead, "TARGET_ARN") == bad_sm, f"DLQ TARGET_ARN={_attr(dead, 'TARGET_ARN')!r}"
    body = json.loads(dead["Body"])
    assert body.get("id") == event_id and body.get("detail") == {"nonce": nonce}, (
        f"the dead-lettered body is not the envelope PutEvents minted (EventId={event_id!r}): "
        f"{body!r}"
    )
    extra = _drain(ctx, dlq_url, seconds=20)
    assert extra == [], (
        f"the DLQ received {len(extra)} further message(s): "
        f"{[(_attr(m, 'RULE_ARN'), _attr(m, 'ERROR_CODE')) for m in extra]!r}"
    )
    denied_ran = _execution_nonces(ctx, bad_sm)
    assert denied_ran == [], (
        f"{len(denied_ran)} execution(s) of {bad_sm} started ({denied_ran!r}) through a role "
        f"events.amazonaws.com cannot assume"
    )
    healthy = sorted(_execution_nonces(ctx, good_sm))
    assert healthy == sorted(good_ran), (
        f"the healthy sibling ran {healthy!r}, expected each delivered nonce once {sorted(good_ran)!r}"
    )

    # REPAIR only the trust policy and demand the identical wiring now start an execution.
    ctx.client("iam").update_assume_role_policy(
        RoleName=bad_role_name, PolicyDocument=_trust("events.amazonaws.com")
    )
    ran, repaired = _repair_and_refire(
        ctx, bus, source, bad_sm,
        description=f"after trusting events.amazonaws.com, {bad_rule} started {bad_sm}",
    )
    assert set(ran) <= set(repaired), (
        f"the repaired rule ran {ran!r}; only post-repair nonces may run, the dead-lettered "
        f"{rounds!r} must not be replayed"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
