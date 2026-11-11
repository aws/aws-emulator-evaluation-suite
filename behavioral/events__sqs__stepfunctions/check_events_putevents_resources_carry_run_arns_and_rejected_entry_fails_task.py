"""events-putevents-resources-carry-run-arns-and-rejected-entry-fails-task."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-putevents-resources-carry-run-arns-and-rejected-entry-fails-task"
GROUP = "service-integration"
SERVICES = ["events", "sqs", "stepfunctions"]

_SOURCE = "sim.sfn.putevents"
_DETAIL_TYPE = "sim2real.putevents.sent"
_ACCESS_RACE_MARKERS = (
    "accessdenied",
    "is not authorized to perform",
    "is not authorized to assume",
    "cannot be assumed",
)


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A Task on arn:aws:states:::events:putEvents appends the execution and state machine
    ARNs to the delivered event's resources; an entry EventBridge rejects fails the state
    with EventBridge.FailedEntry naming the exact entry error.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/connect-eventbridge.html
    """
    sfn = ctx.client("stepfunctions")
    nonce = ctx.unique_name("n")[-12:]

    bus_name, bus_arn = _create_bus(ctx)
    queue = _create_queue(ctx)
    # The rule matches both entries, so a target that accepted the malformed one would route it.
    rule = _create_rule(
        ctx, bus_name,
        {"source": [_SOURCE], "detail": {"nonce": [nonce, f"{nonce}-bad"]}},
    )
    _queue_target(ctx, bus_name, rule, queue)

    role_arn = _create_role(
        ctx, "states.amazonaws.com",
        {"Effect": "Allow", "Action": "events:PutEvents", "Resource": bus_arn},
    )
    definition = {
        "Comment": "sim2real events:putEvents connector probe",
        "StartAt": "Publish",
        "States": {
            "Publish": {
                "Type": "Task",
                "Resource": "arn:aws:states:::events:putEvents",
                "Parameters": {"Entries.$": "$.entries"},
                "End": True,
            },
        },
    }
    sm_arn = _create_state_machine(ctx, _xname(ctx, "sm")[:80], definition, role_arn)

    # Beat 1 — positive control: a well-formed entry is accepted and delivered through the
    # rule to the queue; its resources list carries exactly this run's two ARNs.
    good_input = json.dumps({"entries": [{
        "EventBusName": bus_arn, "Source": _SOURCE, "DetailType": _DETAIL_TYPE,
        "Detail": json.dumps({"nonce": nonce}),
    }]})
    good, good_exec_arn = _run_until_authorized(ctx, sfn, sm_arn, good_input)
    assert good["status"] == "SUCCEEDED", (
        f"the well-formed publish must succeed, got status {good['status']!r}: "
        f"{good.get('error')!r} {good.get('cause')!r}"
    )
    good_output = json.loads(good["output"])
    assert good_output["FailedEntryCount"] == 0, (
        f"the well-formed publish must report FailedEntryCount 0, got {good_output!r}"
    )

    started = time.monotonic()
    delivered = _poll_until(
        ctx,
        lambda: _drain_once(ctx, queue["url"]),
        lambda sink: any(e.get("detail", {}).get("nonce") == nonce for e in sink),
        timeout_s=60, interval_s=1,
        description=f"the queue receives the event carrying nonce {nonce!r}",
    )
    latency_s = time.monotonic() - started
    event = next(e for e in delivered if e["detail"].get("nonce") == nonce)
    assert set(event["resources"]) == {good_exec_arn, sm_arn}, (
        f"the delivered event's resources must be exactly the execution ARN and the state "
        f"machine ARN; got {event.get('resources')!r}"
    )

    # Beat 2 — break exactly one thing: an entry missing the required DetailType field is
    # rejected by EventBridge, and the Task fails the state with EventBridge.FailedEntry.
    bad_input = json.dumps({"entries": [{
        "EventBusName": bus_arn, "Source": _SOURCE,
        "Detail": json.dumps({"nonce": f"{nonce}-bad"}),
    }]})
    bad_exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input=bad_input)["executionArn"]
    ctx.on_cleanup(_teardown(lambda a=bad_exec_arn: _stop_if_running(sfn, a),
                             "ExecutionDoesNotExist"))
    bad = _run_to_terminal(ctx, sfn, bad_exec_arn, timeout_s=60, interval_s=2)
    assert bad["status"] == "FAILED", (
        f"an entry missing DetailType must fail the state, got status {bad['status']!r}"
    )
    assert bad["error"] == "EventBridge.FailedEntry", (
        f"the rejected entry must fail with Error 'EventBridge.FailedEntry', got {bad['error']!r}"
    )
    cause = json.loads(bad["cause"])
    assert cause["FailedEntryCount"] == 1, (
        f"the failure cause must report FailedEntryCount 1, got {cause!r}"
    )
    failed_entry = cause["Entries"][0]
    assert failed_entry["ErrorCode"] == "InvalidArgument", (
        f"the rejected entry's ErrorCode must be 'InvalidArgument', got {failed_entry!r}"
    )
    assert failed_entry["ErrorMessage"] == (
        "Parameter DetailType is not valid. Reason: DetailType is a required argument."
    ), f"the rejected entry's ErrorMessage did not match; got {failed_entry!r}"

    # The rejected entry never reaches the queue, though the rule would route it: held over a
    # window sized from the control's measured delivery latency.
    more = _absent_for(lambda: _drain_once(ctx, queue["url"]), latency_s)
    leaked = [e for e in delivered + more if e.get("detail", {}).get("nonce") == f"{nonce}-bad"]
    assert leaked == [], (
        f"a rejected entry must never be delivered; the queue received {json.dumps(leaked)[:400]}"
    )


# ===== helpers =====
_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"sim2real-xsvc-{kind}-")


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; only not_found codes mean it's gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _stop_if_running(sfn, exec_arn: str) -> None:
    if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=exec_arn)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_until(ctx, probe, predicate, *, timeout_s, interval_s, description):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"{description} not met within {timeout_s:.0f}s. Last result: {last!r}")


def _absent_for(observe, latency_s: float, *, factor: float = 3.0, floor_s: float = 10.0,
                poll_s: float = 1.0) -> list:
    """Everything ``observe()`` returned over ``max(floor_s, factor * latency_s)`` seconds."""
    window = max(floor_s, factor * latency_s)
    deadline = time.monotonic() + window
    seen: list = []
    while True:
        seen.extend(observe())
        if time.monotonic() >= deadline:
            return seen
        time.sleep(poll_s)


def _run_to_terminal(ctx, sfn, exec_arn: str, *, timeout_s: float, interval_s: float) -> dict:
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"execution {exec_arn} was not terminal within {timeout_s:.0f}s: {last!r}")


def _run_until_authorized(ctx, sfn, sm_arn: str, input_str: str, max_attempts: int = 8):
    """Start an execution, retrying while an IAM grant has not yet propagated to the
    authorizer; returns ``(description, executionArn)``. A refused attempt published nothing."""
    desc = None
    exec_arn = None
    for attempt in range(max_attempts):
        exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input=input_str)["executionArn"]
        desc = _run_to_terminal(ctx, sfn, exec_arn, timeout_s=30.0, interval_s=2.0)
        if desc["status"] == "SUCCEEDED":
            return desc, exec_arn
        blob = ((desc.get("cause") or "") + (desc.get("error") or "")).lower()
        if not any(m in blob for m in _ACCESS_RACE_MARKERS):
            return desc, exec_arn
        time.sleep(5 + attempt * 3)
    raise TimeoutError(
        f"events:PutEvents authorization did not propagate after {max_attempts} attempts "
        f"(last execution: {exec_arn}, status {desc['status'] if desc else 'n/a'!r})"
    )


def _create_bus(ctx) -> tuple[str, str]:
    events = ctx.client("events")
    name = _xname(ctx, "bus")[:64]
    arn = events.create_event_bus(
        Name=name, Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["EventBusArn"]

    ctx.on_cleanup(_teardown(lambda n=name: events.delete_event_bus(Name=n),
                             "ResourceNotFoundException"))
    return name, arn


def _create_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = _xname(ctx, "q")[:80]
    url = sqs.create_queue(QueueName=name, tags=dict(_TAGS))["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"name": name, "url": url, "arn": arn}


def _create_rule(ctx, bus_name: str, pattern: dict) -> dict[str, str]:
    events = ctx.client("events")
    name = _xname(ctx, "rule")[:64]
    arn = events.put_rule(
        Name=name, EventBusName=bus_name, EventPattern=json.dumps(pattern),
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["RuleArn"]

    def _delete_rule(n=name):
        ids = [t["Id"] for t in events.list_targets_by_rule(Rule=n, EventBusName=bus_name)["Targets"]]
        if ids:
            events.remove_targets(Rule=n, EventBusName=bus_name, Ids=ids, Force=True)
        events.delete_rule(Name=n, EventBusName=bus_name, Force=True)

    ctx.on_cleanup(_teardown(_delete_rule, "ResourceNotFoundException"))
    return {"name": name, "arn": arn}


def _queue_target(ctx, bus_name: str, rule: dict, queue: dict) -> None:
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue["url"],
        Attributes={"Policy": json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
                           "Action": "sqs:SendMessage", "Resource": queue["arn"],
                           "Condition": {"ArnEquals": {"aws:SourceArn": rule["arn"]}}}],
        })},
    )
    resp = ctx.client("events").put_targets(
        Rule=rule["name"], EventBusName=bus_name, Targets=[{"Id": "q", "Arn": queue["arn"]}],
    )
    assert resp["FailedEntryCount"] == 0, f"PutTargets(queue) failed: {resp['FailedEntries']!r}"


def _create_role(ctx, principal: str, statement: dict) -> str:
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
        _teardown(lambda: iam.delete_role_policy(RoleName=n, PolicyName="inline"), "NoSuchEntity")()
        _teardown(lambda: iam.delete_role(RoleName=n), "NoSuchEntity")()

    ctx.on_cleanup(_delete)
    iam.put_role_policy(
        RoleName=name, PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [statement]}),
    )
    return arn


def _create_state_machine(ctx, name: str, definition: dict, role_arn: str) -> str:
    """Create the machine, retrying only through the IAM role-propagation window."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
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

        ctx.on_cleanup(_teardown(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a),
                                 "StateMachineDoesNotExist"))
        return arn
    raise TimeoutError(
        f"CreateStateMachine({name}) never succeeded within the IAM role-propagation window; "
        f"last error code {last!r}"
    )


def _drain_once(ctx, url: str) -> list:
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
    out = []
    for msg in resp.get("Messages", []):
        sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
        out.append(json.loads(msg["Body"]))
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
