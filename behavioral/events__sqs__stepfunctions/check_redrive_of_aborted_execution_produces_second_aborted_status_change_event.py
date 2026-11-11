"""redrive-of-aborted-execution-produces-second-aborted-status-change-event."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redrive-of-aborted-execution-produces-second-aborted-status-change-event"
GROUP = "event-propagation"
SERVICES = ["events", "sqs", "stepfunctions"]

_SOURCE = "aws.states"
_DETAIL_TYPE = "Step Functions Execution Status Change"
_EVENT_WAIT_S = 240.0
_RELAUNCH_EVERY_S = 60.0

# A single long Wait: the execution only leaves RUNNING because this check stops it.
_DEFINITION = {
    "Comment": "sim2real redrive-of-aborted-execution",
    "StartAt": "Hold",
    "States": {"Hold": {"Type": "Wait", "Seconds": 600, "End": True}},
}


@tags(
    "axis:happy-path",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Redriving an ABORTED Standard execution emits a RUNNING status-change with
    redriveCount 1, and stopping it again emits a SECOND ABORTED status-change, also
    carrying redriveCount 1, not a repeat of the first (redriveCount 0) one."""
    sfn = ctx.client("stepfunctions")

    role_arn = _create_states_role(ctx)
    sm_arn = _create_state_machine(ctx, _xname(ctx, "sm")[:80], _DEFINITION, role_arn)
    queue = _create_queue(ctx)
    _rule_to_queue(
        ctx,
        {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE], "detail": {"stateMachineArn": [sm_arn]}},
        queue,
    )

    sink: list[dict] = []
    launched: list[str] = []

    def _stop_all() -> None:
        for arn in launched:
            _tolerate(lambda a=arn: sfn.stop_execution(executionArn=a), "ExecutionDoesNotExist",
                      leak=f"could not stop execution {arn}")

    ctx.on_cleanup(_stop_all)

    def _events_for(arn: str, status: str) -> list[dict]:
        return [b for b in sink
                if b["detail"].get("executionArn") == arn and b["detail"].get("status") == status]

    # Launch (relaunching while the bus rule is not yet live) until one execution's RUNNING
    # event has been delivered.
    exec_arn = None
    t0 = time.monotonic()
    deadline = t0 + _EVENT_WAIT_S
    last_launch = float("-inf")
    while time.monotonic() < deadline and exec_arn is None:
        if time.monotonic() - last_launch > _RELAUNCH_EVERY_S:
            arn = sfn.start_execution(stateMachineArn=sm_arn, name=_xname(ctx, "ex")[:80],
                                      input=json.dumps({"attempt": len(launched)}))["executionArn"]
            launched.append(arn)
            last_launch = time.monotonic()
        _drain_once(ctx, queue["url"], sink)
        for arn in launched:
            if _events_for(arn, "RUNNING"):
                exec_arn = arn
                break
    assert exec_arn is not None, (
        f"within {_EVENT_WAIT_S:.0f}s the bus never delivered a RUNNING event for any of "
        f"{len(launched)} launched execution(s)"
    )
    first_running = _events_for(exec_arn, "RUNNING")[0]["detail"]
    assert (first_running["redriveCount"], first_running["redriveStatus"]) == (0, "NOT_REDRIVABLE"), (
        f"the first RUNNING event must read redriveCount 0, NOT_REDRIVABLE; got "
        f"{(first_running.get('redriveCount'), first_running.get('redriveStatus'))!r}"
    )

    token1 = ctx.unique_name("t")[-12:]
    stop_error1, stop_cause1 = f"Sim2Real.Stop1.{token1}", f"first stop {token1}"
    sfn.stop_execution(executionArn=exec_arn, error=stop_error1, cause=stop_cause1)

    _poll_until(
        lambda: _drain_once(ctx, queue["url"], sink),
        lambda _s: bool(_events_for(exec_arn, "ABORTED")),
        timeout_s=_EVENT_WAIT_S, interval_s=0.5,
        description=f"a first ABORTED status-change for {exec_arn}",
    )
    first_aborted = [b for b in _events_for(exec_arn, "ABORTED")][0]["detail"]
    assert (first_aborted["redriveCount"], first_aborted["redriveStatus"]) == (0, "REDRIVABLE"), (
        f"the first ABORTED event must read redriveCount 0, REDRIVABLE; got "
        f"{(first_aborted.get('redriveCount'), first_aborted.get('redriveStatus'))!r}"
    )
    assert (first_aborted["error"], first_aborted["cause"]) == (stop_error1, stop_cause1), (
        f"the first ABORTED event must carry the first StopExecution's error/cause "
        f"{(stop_error1, stop_cause1)!r}; got {(first_aborted.get('error'), first_aborted.get('cause'))!r}"
    )
    described_after_first_stop = sfn.describe_execution(executionArn=exec_arn)
    assert described_after_first_stop["redriveStatus"] == "REDRIVABLE", (
        f"DescribeExecution must agree the ABORTED execution is REDRIVABLE; got "
        f"{described_after_first_stop.get('redriveStatus')!r}"
    )

    redrive_ms = _epoch_ms(sfn.redrive_execution(executionArn=exec_arn)["redriveDate"])

    def _redriven_running() -> list[dict]:
        return [b for b in _events_for(exec_arn, "RUNNING") if b["detail"]["redriveCount"] == 1]

    _poll_until(
        lambda: _drain_once(ctx, queue["url"], sink),
        lambda _s: bool(_redriven_running()),
        timeout_s=_EVENT_WAIT_S, interval_s=0.5,
        description=f"a redriven RUNNING event (redriveCount 1) for {exec_arn}",
    )
    redriven_running = _redriven_running()[0]["detail"]
    assert redriven_running["redriveStatus"] == "NOT_REDRIVABLE", (
        f"a RUNNING execution cannot itself be redriven; got redriveStatus "
        f"{redriven_running.get('redriveStatus')!r}"
    )
    assert redriven_running["redriveDate"] == redrive_ms, (
        f"the redriven RUNNING event's redriveDate must equal RedriveExecution's redriveDate "
        f"{redrive_ms}; got {redriven_running.get('redriveDate')!r}"
    )
    assert redriven_running["startDate"] == first_running["startDate"], (
        f"a redrive keeps the execution's original startDate {first_running['startDate']!r}; "
        f"the redriven RUNNING event has {redriven_running.get('startDate')!r}"
    )
    described_after_redrive = sfn.describe_execution(executionArn=exec_arn)
    assert (described_after_redrive["status"], described_after_redrive["redriveCount"]) == ("RUNNING", 1), (
        f"DescribeExecution must agree the execution is RUNNING with redriveCount 1; got "
        f"{(described_after_redrive['status'], described_after_redrive.get('redriveCount'))!r}"
    )

    token2 = ctx.unique_name("t")[-12:]
    stop_error2, stop_cause2 = f"Sim2Real.Stop2.{token2}", f"second stop {token2}"
    sfn.stop_execution(executionArn=exec_arn, error=stop_error2, cause=stop_cause2)

    def _second_aborted() -> list[dict]:
        return [b for b in _events_for(exec_arn, "ABORTED") if b["detail"]["redriveCount"] == 1]

    _poll_until(
        lambda: _drain_once(ctx, queue["url"], sink),
        lambda _s: bool(_second_aborted()),
        timeout_s=_EVENT_WAIT_S, interval_s=0.5,
        description=f"a second ABORTED status-change (redriveCount 1) for {exec_arn}",
    )
    second_aborted = _second_aborted()[0]["detail"]
    assert second_aborted["redriveStatus"] == "REDRIVABLE", (
        f"the second ABORTED event must read REDRIVABLE; got {second_aborted.get('redriveStatus')!r}"
    )
    assert (second_aborted["error"], second_aborted["cause"]) == (stop_error2, stop_cause2), (
        f"the second ABORTED event must carry the SECOND StopExecution's error/cause "
        f"{(stop_error2, stop_cause2)!r}, not the first; got "
        f"{(second_aborted.get('error'), second_aborted.get('cause'))!r}"
    )
    assert second_aborted["startDate"] == first_running["startDate"], (
        f"the second ABORTED event must keep the original startDate {first_running['startDate']!r}; "
        f"got {second_aborted.get('startDate')!r}"
    )
    assert second_aborted["stopDate"] >= redrive_ms, (
        f"the second ABORTED event's stopDate must be at or after the redriveDate {redrive_ms}; "
        f"got {second_aborted.get('stopDate')!r}"
    )
    # The queue target delivers at least once, so a redelivered event is counted once by its id.
    aborted = {b["id"]: b["detail"].get("redriveCount") for b in _events_for(exec_arn, "ABORTED")}
    assert len(aborted) == 2, (
        f"exactly two distinct ABORTED events must have been delivered for {exec_arn}; got "
        f"redriveCounts {sorted(aborted.values())!r}"
    )

    described_final = sfn.describe_execution(executionArn=exec_arn)
    assert (described_final["status"], described_final["redriveCount"]) == ("ABORTED", 1), (
        f"DescribeExecution must agree with the events: ABORTED, redriveCount 1; got "
        f"{(described_final['status'], described_final.get('redriveCount'))!r}"
    )
    assert (described_final.get("error"), described_final.get("cause")) == (stop_error2, stop_cause2), (
        f"DescribeExecution must carry the second stop's error/cause; got "
        f"{(described_final.get('error'), described_final.get('cause'))!r}"
    )


def _epoch_ms(value) -> int:
    return int(round(value.timestamp() * 1000))


# ===== helpers =====
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


def _create_states_role(ctx) -> str:
    """A role Step Functions can assume. A Wait state needs no permissions beyond that."""
    iam = ctx.client("iam")
    name = _xname(ctx, "role")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["Role"]["Arn"]

    def _delete(n=name):
        _tolerate(lambda: iam.delete_role(RoleName=n), "NoSuchEntity", leak=f"could not delete role {n}")

    ctx.on_cleanup(_delete)
    return arn


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
            time.sleep(2)
            continue

        def _delete(a=arn):
            _tolerate(lambda: sfn.delete_state_machine(stateMachineArn=a), "StateMachineDoesNotExist",
                      leak=f"could not delete state machine {a}")

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


def _rule_to_queue(ctx, pattern: dict, queue: dict) -> str:
    """A rule on the DEFAULT bus (where AWS service events land) with this queue as sole target."""
    events = ctx.client("events")
    name = _xname(ctx, "rule")[:64]
    arn = events.put_rule(
        Name=name, EventPattern=json.dumps(pattern),
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["RuleArn"]

    def _teardown(n=name):
        _tolerate(lambda: events.remove_targets(Rule=n, Ids=["q"], Force=True),
                  "ResourceNotFoundException", leak=f"could not remove target from rule {n}")
        _tolerate(lambda: events.delete_rule(Name=n, Force=True),
                  "ResourceNotFoundException", leak=f"could not delete rule {n}")

    ctx.on_cleanup(_teardown)
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue["url"],
        Attributes={"Policy": json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
                           "Action": "sqs:SendMessage", "Resource": queue["arn"],
                           "Condition": {"ArnEquals": {"aws:SourceArn": arn}}}],
        })},
    )
    events.put_targets(Rule=name, Targets=[{"Id": "q", "Arn": queue["arn"]}])
    return arn


def _drain_once(ctx, url: str, sink: list) -> list:
    """One long-poll receive; every Step Functions status-change body is appended to sink."""
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
    for msg in resp.get("Messages", []):
        sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
        body = json.loads(msg["Body"])
        if body.get("source") == _SOURCE and body.get("detail-type") == _DETAIL_TYPE:
            sink.append(body)
    return sink


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
