"""xsvc-iam-3-events-role-starts-sfn-execution-with-the-event-as-input."""

from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-iam-3-events-role-starts-sfn-execution-with-the-event-as-input"
GROUP = "permission-chain"
SERVICES = ["events", "iam", "stepfunctions", "sqs"]

_DETAIL_TYPE = "Sim2realOrderPlaced"
_NEAR_MISS_DETAIL_TYPE = "Sim2realOrderCancelled"


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

@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c7",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A target role trusting events.amazonaws.com with states:StartExecution starts one execution
    whose input is the full delivered envelope; a near-miss event starts nothing; the DLQ stays
    empty.
    """
    events = ctx.client("events")
    ident = ctx.client("sts").get_caller_identity()
    account = ident["Account"]
    partition = ident["Arn"].split(":")[1]
    suffix = uuid.uuid4().hex[:10]
    source = f"sim2real.xsvc.iam3.{suffix}"
    sm_name = f"sim2real-xsvc-iam3-sm-{suffix}"
    sm_arn_expected = f"arn:{partition}:states:{ctx.region}:{account}:stateMachine:{sm_name}"

    # Roles first, so they have propagated by the time the first event is delivered.
    target_role = _create_role(
        ctx,
        f"sim2real-xsvc-iam3-evr-{suffix}",
        "events.amazonaws.com",
        [{"Effect": "Allow", "Action": "states:StartExecution", "Resource": sm_arn_expected}],
    )
    sm_role = _create_role(ctx, f"sim2real-xsvc-iam3-smr-{suffix}", "states.amazonaws.com", [])
    sm_arn = _create_state_machine(
        ctx,
        sm_name,
        sm_role,
        {
            "StartAt": "Project",
            "States": {
                "Project": {
                    "Type": "Pass",
                    "Parameters": {
                        "eventId.$": "$.id",
                        "nonce.$": "$.detail.nonce",
                        "source.$": "$.source",
                    },
                    "End": True,
                }
            },
        },
    )
    assert sm_arn == sm_arn_expected, f"state machine ARN {sm_arn!r} != {sm_arn_expected!r}"

    bus = ctx.unique_name("sim2real-xsvc-iam3-bus-")
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ctx.client("events").delete_event_bus(Name=bus))
    dlq_url, dlq_arn = _create_dlq(
        ctx,
        f"sim2real-xsvc-iam3-dlq-{suffix}",
        f"arn:{partition}:events:{ctx.region}:{account}:rule/{bus}/*",
    )
    rule = ctx.unique_name("sim2real-xsvc-iam3-rule-")
    rule_arn = _make_rule(
        ctx,
        bus,
        rule,
        {"source": [source], "detail-type": [_DETAIL_TYPE]},
        {
            "Id": "sfn",
            "Arn": sm_arn,
            "RoleArn": target_role,
            "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
            "DeadLetterConfig": {"Arn": dlq_arn},
        },
    )

    near_miss = {
        "EventBusName": bus,
        "Source": source,
        "DetailType": _NEAR_MISS_DETAIL_TYPE,
        "Detail": json.dumps({"nonce": f"near-miss-{suffix}"}),
    }
    t_put = time.monotonic()
    # A delivery racing the new role's IAM propagation is dead-lettered with FAILED_TO_ASSUME_ROLE
    # rather than retried, so only that code re-fires the round.
    for _ in range(3):
        nonce, event_id, dead, strays = _deliver_round(
            ctx, bus, source, dlq_url, {rule_arn: sm_arn}, extra_entries=[near_miss]
        )
        assert strays == [], (
            f"the DLQ held copies this round did not produce: "
            f"{[(_attr(m, 'RULE_ARN'), m['Body'][:120]) for m in strays]!r}"
        )
        if rule_arn not in dead:
            break
        assert _attr(dead[rule_arn], "ERROR_CODE") == "FAILED_TO_ASSUME_ROLE", (
            f"a correctly trusted and permitted role was dead-lettered with ERROR_CODE="
            f"{_attr(dead[rule_arn], 'ERROR_CODE')!r}: {_attr(dead[rule_arn], 'ERROR_MESSAGE')!r}"
        )
        t_put = time.monotonic()
    assert rule_arn not in dead, (
        f"three rounds all dead-lettered (last ERROR_MESSAGE="
        f"{_attr(dead[rule_arn], 'ERROR_MESSAGE')!r}); the role never became usable"
    )
    t_arrival = time.monotonic()

    runs = [(d, body) for d, body in _execution_inputs(ctx, sm_arn) if body["detail"]["nonce"] == nonce]
    assert len(runs) == 1, f"{len(runs)} executions carry nonce {nonce!r}, expected exactly 1"
    exec_arn = runs[0][0]["executionArn"]
    desc = _poll_until(
        lambda: ctx.client("stepfunctions").describe_execution(executionArn=exec_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=60,
        interval_s=2,
        description=f"execution {exec_arn} left RUNNING",
    )
    assert desc["status"] == "SUCCEEDED", (
        f"execution ended {desc['status']!r}, expected SUCCEEDED: {desc.get('error')!r} "
        f"{desc.get('cause')!r}"
    )

    envelope = json.loads(desc["input"])
    assert envelope.get("id") == event_id, (
        f"execution input id={envelope.get('id')!r}, expected the EventId PutEvents returned "
        f"{event_id!r} — the input must be the delivered envelope, not a synthesised one"
    )
    assert envelope.get("source") == source, f"input source={envelope.get('source')!r}"
    assert envelope.get("detail-type") == _DETAIL_TYPE, (
        f"input detail-type={envelope.get('detail-type')!r}, expected {_DETAIL_TYPE!r}"
    )
    assert envelope.get("detail") == {"nonce": nonce}, (
        f"input detail={envelope.get('detail')!r}, expected {{'nonce': {nonce!r}}}"
    )
    assert envelope.get("account") == account, f"input account={envelope.get('account')!r}"
    assert envelope.get("region") == ctx.region, f"input region={envelope.get('region')!r}"

    output = json.loads(desc["output"])
    assert output == {"eventId": event_id, "nonce": nonce, "source": source}, (
        f"the state machine's output {output!r} was not computed from the delivered input"
    )

    # The near-miss entry (same source, other detail-type) was in the SAME PutEvents call, so the
    # matching execution's arrival is the barrier: hold well past it and require nothing further.
    hold = min(max(3 * (t_arrival - t_put), 30.0), 90.0)
    leaked = _drain(ctx, dlq_url, seconds=hold)
    assert leaked == [], (
        f"the rule's DLQ received {len(leaked)} message(s) after a successful delivery: "
        f"{[(_attr(m, 'ERROR_CODE'), m['Body'][:120]) for m in leaked]!r}"
    )
    ran = _execution_nonces(ctx, sm_arn)
    assert ran == [nonce], (
        f"executions carry nonces {ran!r}, expected exactly [{nonce!r}] — the near-miss "
        f"detail-type {_NEAR_MISS_DETAIL_TYPE!r} must not match, and one delivered event starts "
        f"one execution"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
