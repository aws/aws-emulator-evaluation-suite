"""xsvc-sfn-2-dlq-missing-permission."""

from __future__ import annotations

import datetime as dt
import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-sfn-2-dlq-missing-permission"
GROUP = "event-propagation"
SERVICES = ["events", "stepfunctions", "sqs"]

_SOURCE = "sim2real.xsvc.dlq"
_DETAIL_TYPE = "job.submitted"
_REPUBLISH_EVERY_S = 20.0
_DELIVERY_BUDGET_S = 120.0
_METRIC_BUDGET_S = 150.0

_DEFINITION = {
    "Comment": "sim2real xsvc-sfn-2 EventBridge target",
    "StartAt": "Done",
    "States": {"Done": {"Type": "Pass", "End": True}},
}


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-monitoring.html
@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """A state machine target whose role lacks states:StartExecution starts nothing while a permitted
    twin does; its event lands in the target DLQ with ERROR_CODE NO_PERMISSIONS and the rule and
    target ARNs, InvocationsSentToDlq counts it, and the grant lets the same target start one."""
    sfn = ctx.client("stepfunctions")
    events = ctx.client("events")
    nonce = ctx.unique_name("n")[-12:]

    bus_name, _ = _create_bus(ctx)
    dlq = _create_queue(ctx)

    good_role = _create_events_role(ctx, allow_start=True)
    bad_role = _create_events_role(ctx, allow_start=False)
    states_role = _create_states_role(ctx)
    # Two identical machines, so "the broken target started nothing" is a query over a machine
    # only the broken target points at, rather than a count that at-least-once delivery could skew.
    sm_good = _create_state_machine(ctx, _xname(ctx, "smg")[:80], _DEFINITION, states_role)
    sm_bad = _create_state_machine(ctx, _xname(ctx, "smb")[:80], _DEFINITION, states_role)

    rule = _create_rule(
        ctx, bus_name, {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE], "detail": {"nonce": [nonce]}},
    )
    _allow_events_to_queue(ctx, dlq, rule["arn"])
    resp = events.put_targets(Rule=rule["name"], EventBusName=bus_name, Targets=[
        {"Id": "bad", "Arn": sm_bad, "RoleArn": bad_role["arn"],
         "DeadLetterConfig": {"Arn": dlq["arn"]}},
        {"Id": "good", "Arn": sm_good, "RoleArn": good_role["arn"]},
    ])
    assert resp["FailedEntryCount"] == 0, f"PutTargets failed: {resp['FailedEntries']!r}"

    window_start = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=2)
    published: dict[str, str] = {}

    def _publish() -> str:
        job = f"job-{nonce}-{len(published)}"
        r = events.put_events(Entries=[{
            "EventBusName": bus_name, "Source": _SOURCE, "DetailType": _DETAIL_TYPE,
            "Detail": json.dumps({"nonce": nonce, "job": job}),
        }])
        assert r["FailedEntryCount"] == 0, f"PutEvents failed: {r['Entries']!r}"
        published[job] = r["Entries"][0]["EventId"]
        return job

    # Publish, re-publishing with a fresh job id until the GOOD target has started an execution
    # from one of them: that execution proves the rule matched and a machine was startable.
    started = _publish_until(_publish, lambda: _executions_by_job(sfn, sm_good))
    assert len(started) >= 1 and set(started) <= set(published), (
        f"the target whose role HAS states:StartExecution must start an execution within "
        f"{_DELIVERY_BUDGET_S:.0f}s, from one of this check's events; published "
        f"{sorted(published)!r}, started {sorted(started)!r}"
    )

    # The broken target's dead letter, for an event the good target provably processed. A dead
    # letter from before the broken role's TRUST propagated reads FAILED_TO_ASSUME_ROLE
    # and says nothing about the permission, so keep publishing until a NO_PERMISSIONS one exists.
    dlq_msgs: list[dict] = []

    def _no_permission_letter():
        _drain_dlq(ctx, dlq["url"], dlq_msgs)
        started.update(_executions_by_job(sfn, sm_good))
        for m in dlq_msgs:
            code = (m.get("MessageAttributes", {}).get("ERROR_CODE") or {}).get("StringValue")
            if code == "NO_PERMISSIONS" and json.loads(m["Body"]).get("detail", {}).get("job") in started:
                return {"m": m}
        return {}

    found = _publish_until(_publish, _no_permission_letter)
    assert sorted(found) == ["m"], (
        f"within {_DELIVERY_BUDGET_S:.0f}s the DLQ must receive a NO_PERMISSIONS dead letter for an "
        f"event the good target processed; dead letters seen: "
        f"{[(m.get('MessageAttributes', {}).get('ERROR_CODE'), m['Body'][:120]) for m in dlq_msgs]!r}"
    )
    msg = found["m"]
    body = json.loads(msg["Body"])
    attrs = {k: v.get("StringValue") for k, v in msg.get("MessageAttributes", {}).items()}
    job = body["detail"]["job"]
    assert body["id"] == published[job], (
        f"the dead letter must be the original event (id {published[job]!r}); got id {body.get('id')!r}"
    )
    assert body["source"] == _SOURCE and body["detail-type"] == _DETAIL_TYPE, (
        f"the dead letter's envelope must be the original ({_SOURCE!r}, {_DETAIL_TYPE!r}); got "
        f"({body.get('source')!r}, {body.get('detail-type')!r})"
    )
    assert body["detail"] == {"nonce": nonce, "job": job}, (
        f"the dead letter must carry the original detail; got {body.get('detail')!r}"
    )
    assert attrs.get("ERROR_CODE") == "NO_PERMISSIONS", (
        f"the dead letter's ERROR_CODE attribute must be NO_PERMISSIONS for a role lacking "
        f"states:StartExecution; got attributes {attrs!r}"
    )
    err_msg = attrs.get("ERROR_MESSAGE") or ""
    assert "states:StartExecution" in err_msg and bad_role["name"] in err_msg, (
        f"ERROR_MESSAGE must name the refused action and the broken role {bad_role['name']!r}; "
        f"got {err_msg!r}"
    )
    assert attrs.get("RULE_ARN") == rule["arn"] and attrs.get("TARGET_ARN") == sm_bad, (
        f"the dead letter must name the rule {rule['arn']!r} and the broken target's machine "
        f"{sm_bad!r}; got {attrs!r}"
    )

    # Effect absent: the broken target's machine has never run, after the good side delivered.
    bad_runs = _executions_by_job(sfn, sm_bad)
    assert bad_runs == {}, (
        f"a target whose role lacks states:StartExecution must start nothing; its machine has "
        f"executions {bad_runs!r}"
    )

    # The metric: InvocationsSentToDlq, on the (EventBusName, RuleName) dimension pair a
    # custom-bus rule reports under.
    cw = ctx.client("cloudwatch")

    def _dlq_sum() -> float:
        r = cw.get_metric_statistics(
            Namespace="AWS/Events", MetricName="InvocationsSentToDlq",
            Dimensions=[{"Name": "EventBusName", "Value": bus_name},
                        {"Name": "RuleName", "Value": rule["name"]}],
            StartTime=window_start,
            EndTime=dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=2),
            Period=60, Statistics=["Sum"],
        )
        return sum(p["Sum"] for p in r["Datapoints"])

    total = _poll_until(_dlq_sum, lambda v: v >= 1, timeout_s=_METRIC_BUDGET_S, interval_s=10,
                        description="AWS/Events InvocationsSentToDlq records a datapoint for the rule")
    assert total <= len(published), (
        f"InvocationsSentToDlq ({total}) cannot exceed the number of events published "
        f"({len(published)})"
    )

    # Repair the one broken thing: grant states:StartExecution to the broken target's role, and
    # require the SAME target to start its machine — the wiring was sound all along.
    _put_policy(ctx, bad_role["name"], {"Effect": "Allow", "Action": "states:StartExecution",
                                        "Resource": "*"})
    repaired = _publish_until(_publish, lambda: _executions_by_job(sfn, sm_bad))
    assert len(repaired) >= 1, (
        f"after granting states:StartExecution, the same target must start its machine within "
        f"{_DELIVERY_BUDGET_S:.0f}s; published {sorted(published)!r}"
    )
    assert set(repaired) <= set(published), (
        f"the repaired target's executions must come from this check's events; got {repaired!r}"
    )


def _publish_until(publish, probe) -> dict:
    """Publish, republishing every _REPUBLISH_EVERY_S, until probe() is non-empty or budget ends."""
    t0 = time.monotonic()
    last_pub = float("-inf")
    found: dict = {}
    while time.monotonic() - t0 < _DELIVERY_BUDGET_S:
        if time.monotonic() - last_pub > _REPUBLISH_EVERY_S:
            publish()
            last_pub = time.monotonic()
        found = probe()
        if found:
            return found
        time.sleep(2)
    return found


_XSVC_PREFIX = "sim2real-xsvc-"
_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _tolerate(fn, *tolerated: str, leak: str = "") -> None:
    """Run a teardown call. With a leak label, an error code outside `tolerated` is reported as a
    leak; without one, a refused teardown call is ignored."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if leak and code not in tolerated:
            raise RuntimeError(f"{leak}: {code}") from exc


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll until predicate holds; RAISE on timeout (never return the last value)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _executions_by_job(sfn, sm_arn: str) -> dict:
    """job id -> execution ARN for every execution of sm_arn (the input is the whole event)."""
    out: dict = {}
    for page in sfn.get_paginator("list_executions").paginate(stateMachineArn=sm_arn):
        for ex in page["executions"]:
            inp = json.loads(sfn.describe_execution(executionArn=ex["executionArn"])["input"])
            out[inp.get("detail", {}).get("job")] = ex["executionArn"]
    return out


def _create_bus(ctx) -> tuple[str, str]:
    events = ctx.client("events")
    name = _xname(ctx, "bus")[:64]
    arn = events.create_event_bus(
        Name=name, Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["EventBusArn"]

    def _delete(n=name):
        _tolerate(lambda: events.delete_event_bus(Name=n), "ResourceNotFoundException", leak=f"could not delete event bus {n}")

    ctx.on_cleanup(_delete)
    return name, arn


def _create_role(ctx, principal: str, statement: dict) -> dict:
    iam = ctx.client("iam")
    name = _xname(ctx, "role")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": principal},
                       "Action": "sts:AssumeRole"}],
    }
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["Role"]["Arn"]

    def _delete(n=name):
        _tolerate(lambda: iam.delete_role_policy(RoleName=n, PolicyName="inline"))
        _tolerate(lambda: iam.delete_role(RoleName=n), "NoSuchEntity", leak=f"could not delete role {n}")

    ctx.on_cleanup(_delete)
    _put_policy(ctx, name, statement)
    time.sleep(8)  # IAM propagation; the republish loops at first use are the guard
    return {"name": name, "arn": arn}


def _put_policy(ctx, role_name: str, statement: dict) -> None:
    ctx.client("iam").put_role_policy(
        RoleName=role_name, PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [statement]}),
    )


def _create_events_role(ctx, *, allow_start: bool) -> dict:
    """An EventBridge-assumable role. The broken one is identical except that its one statement
    grants a harmless read instead of states:StartExecution — exactly one thing differs."""
    action = "states:StartExecution" if allow_start else "states:DescribeStateMachine"
    return _create_role(ctx, "events.amazonaws.com",
                        {"Effect": "Allow", "Action": action, "Resource": "*"})


def _create_states_role(ctx) -> str:
    """The machines are a single Pass state, so their own role needs no permission at all."""
    return _create_role(ctx, "states.amazonaws.com",
                        {"Effect": "Deny", "Action": "states:SendTaskSuccess", "Resource": "*"})["arn"]


def _create_state_machine(ctx, name: str, definition: dict, role_arn: str) -> str:
    """Create the machine, retrying only through the IAM role-propagation window."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 90
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD",
                tags=[{"key": k, "value": v} for k, v in _TAGS.items()],
            )["stateMachineArn"]
        except ClientError as exc:
            last = exc.response.get("Error", {}).get("Code")
            if last != "AccessDeniedException":
                raise
            time.sleep(3)
            continue

        def _delete(a=arn):
            _tolerate(lambda: sfn.delete_state_machine(stateMachineArn=a), "StateMachineDoesNotExist", leak=f"could not delete state machine {a}")

        ctx.on_cleanup(_delete)
        return arn
    raise AssertionError(
        f"CreateStateMachine({name}) never succeeded within the IAM role-propagation window; "
        f"last error code {last!r}"
    )


def _create_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = _xname(ctx, "q")[:80]
    url = sqs.create_queue(QueueName=name, tags=dict(_TAGS))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"name": name, "url": url, "arn": arn}


def _allow_events_to_queue(ctx, queue: dict, rule_arn: str) -> None:
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue["url"],
        Attributes={"Policy": json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
                           "Action": "sqs:SendMessage", "Resource": queue["arn"],
                           "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}}}],
        })},
    )


def _create_rule(ctx, bus_name: str, pattern: dict) -> dict[str, str]:
    events = ctx.client("events")
    name = _xname(ctx, "rule")[:64]
    arn = events.put_rule(
        Name=name, EventBusName=bus_name, EventPattern=json.dumps(pattern),
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["RuleArn"]

    def _teardown(n=name):
        ids = [t["Id"] for t in events.list_targets_by_rule(Rule=n, EventBusName=bus_name)["Targets"]]
        if ids:
            _tolerate(lambda: events.remove_targets(Rule=n, EventBusName=bus_name, Ids=ids, Force=True))
        _tolerate(lambda: events.delete_rule(Name=n, EventBusName=bus_name, Force=True), "ResourceNotFoundException", leak=f"could not delete rule {n}")

    ctx.on_cleanup(_teardown)
    return {"name": name, "arn": arn}


def _drain_dlq(ctx, url: str, sink: list) -> list:
    """One long-poll receive with every message attribute; raw messages are appended to sink."""
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2,
                               MessageAttributeNames=["All"])
    for msg in resp.get("Messages", []):
        sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
        sink.append(msg)
    return sink


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
