"""xsvc-sfn-2-dlq-twin-with-permission-starts-execution."""

from __future__ import annotations

import datetime as dt
import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-sfn-2-dlq-twin-with-permission-starts-execution"
GROUP = "event-propagation"
SERVICES = ["events", "stepfunctions", "sqs"]

_SOURCE = "sim2real.xsvc.dlq"
_DETAIL_TYPE = "job.submitted"
_REPUBLISH_EVERY_S = 20.0
_DELIVERY_BUDGET_S = 120.0
_METRIC_BUDGET_S = 150.0
_DRAIN_EXTRA = 3

_DEFINITION = {
    "Comment": "sim2real xsvc-sfn-2 EventBridge target",
    "StartAt": "Done",
    "States": {"Done": {"Type": "Pass", "End": True}},
}


# timing:real-time — metric: 37 s https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-monitoring.html
@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """A state machine target whose role grants states:StartExecution starts an execution with the
    whole event as input that reaches SUCCEEDED; Invocations counts it while the DLQ and
    InvocationsSentToDlq stay empty."""
    sfn = ctx.client("stepfunctions")
    events = ctx.client("events")
    account = ctx.client("sts").get_caller_identity()["Account"]
    nonce = ctx.unique_name("n")[-12:]

    bus_name, _ = _create_bus(ctx)
    dlq = _create_queue(ctx)
    role = _create_events_role(ctx, allow_start=True)
    states_role = _create_states_role(ctx)
    sm_arn = _create_state_machine(ctx, _xname(ctx, "sm")[:80], _DEFINITION, states_role)

    rule = _create_rule(
        ctx, bus_name, {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE], "detail": {"nonce": [nonce]}},
    )
    _allow_events_to_queue(ctx, dlq, rule["arn"])
    resp = events.put_targets(Rule=rule["name"], EventBusName=bus_name, Targets=[
        {"Id": "t", "Arn": sm_arn, "RoleArn": role["arn"], "DeadLetterConfig": {"Arn": dlq["arn"]}},
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

    started = _publish_until(_publish, lambda: _executions_by_job(sfn, sm_arn))
    assert len(started) >= 1 and set(started) <= set(published), (
        f"a target whose role grants states:StartExecution must start an execution within "
        f"{_DELIVERY_BUDGET_S:.0f}s, from one of this check's events; published "
        f"{sorted(published)!r}, started {sorted(started)!r}"
    )
    # The role is now provably assumable. Every event published from here on must start an
    # execution and must never be dead-lettered.
    pre_barrier = set(published)
    post = [_publish(), _publish()]
    runs = _poll_until(
        lambda: _executions_by_job(sfn, sm_arn),
        lambda r: all(j in r for j in post), timeout_s=_DELIVERY_BUDGET_S, interval_s=2,
        description=f"both post-barrier events {post!r} start an execution",
    )
    for job in post:
        exec_arn = runs[job]
        described = _poll_until(
            lambda a=exec_arn: sfn.describe_execution(executionArn=a),
            lambda d: d["status"] != "RUNNING", timeout_s=60, interval_s=1,
            description=f"execution {exec_arn} leaves RUNNING",
        )
        assert described["status"] == "SUCCEEDED", (
            f"the started execution must SUCCEED; got {described['status']!r} "
            f"({described.get('error')!r}: {described.get('cause')!r})"
        )
        event = json.loads(described["input"])
        assert event["id"] == published[job], (
            f"the execution input must be the published event (id {published[job]!r}); got "
            f"{event.get('id')!r}"
        )
        assert (event["source"], event["detail-type"]) == (_SOURCE, _DETAIL_TYPE), (
            f"the input envelope must be ({_SOURCE!r}, {_DETAIL_TYPE!r}); got "
            f"({event.get('source')!r}, {event.get('detail-type')!r})"
        )
        assert (event["account"], event["region"]) == (account, ctx.region), (
            f"the input envelope must be attributed to {account!r}/{ctx.region!r}; got "
            f"{event.get('account')!r}/{event.get('region')!r}"
        )
        assert event["detail"] == {"nonce": nonce, "job": job}, (
            f"the input must carry the published detail verbatim; got {event.get('detail')!r}"
        )
        assert json.loads(described["output"]) == event, (
            f"a Pass-only machine's output must equal its input; got {described.get('output')!r}"
        )

    cw = ctx.client("cloudwatch")

    def _sum(metric: str) -> float:
        r = cw.get_metric_statistics(
            Namespace="AWS/Events", MetricName=metric,
            Dimensions=[{"Name": "EventBusName", "Value": bus_name},
                        {"Name": "RuleName", "Value": rule["name"]}],
            StartTime=window_start,
            EndTime=dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=2),
            Period=60, Statistics=["Sum"],
        )
        return sum(p["Sum"] for p in r["Datapoints"])

    _poll_until(lambda: _sum("Invocations"), lambda v: v >= len(post),
                timeout_s=_METRIC_BUDGET_S, interval_s=10,
                description=f"AWS/Events Invocations counts at least the {len(post)} post-barrier invocations")

    # The failure path: no post-barrier event was dead-lettered. A dead letter from BEFORE the
    # barrier is legitimate only as a trust-propagation failure for an event that never started.
    dlq_msgs: list[dict] = []
    for _ in range(_DRAIN_EXTRA):
        _drain_dlq(ctx, dlq["url"], dlq_msgs)
    final_runs = _executions_by_job(sfn, sm_arn)
    for m in dlq_msgs:
        job = json.loads(m["Body"]).get("detail", {}).get("job")
        code = (m.get("MessageAttributes", {}).get("ERROR_CODE") or {}).get("StringValue")
        assert job in pre_barrier and job not in final_runs and code == "FAILED_TO_ASSUME_ROLE", (
            f"a target whose role grants states:StartExecution may dead-letter only a pre-barrier "
            f"event it never started, for FAILED_TO_ASSUME_ROLE; got job {job!r} "
            f"(pre-barrier={job in pre_barrier}, started={job in final_runs}) with ERROR_CODE {code!r}"
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
