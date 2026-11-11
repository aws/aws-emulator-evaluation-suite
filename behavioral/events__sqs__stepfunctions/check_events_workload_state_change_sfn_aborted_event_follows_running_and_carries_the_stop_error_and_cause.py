"""events-workload-state-change-sfn-aborted-event-follows-running-and-carries-the-stop-error-and-cause."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

# AWS behavior: a Standard execution emits a RUNNING status-change (stopDate/error/cause/output
# null, redriveStatus NOT_REDRIVABLE), and StopExecution(error, cause) then produces an ABORTED
# status-change whose detail.error and detail.cause are the strings passed to StopExecution and
# whose redriveStatus is REDRIVABLE.

CHECK = "events-workload-state-change-sfn-aborted-event-follows-running-and-carries-the-stop-error-and-cause"
GROUP = "event-propagation"
SERVICES = ["events", "stepfunctions", "sqs"]

_SOURCE = "aws.states"
_DETAIL_TYPE = "Step Functions Execution Status Change"
_EVENT_WAIT_S = 240.0
_RELAUNCH_EVERY_S = 60.0
_MIN_SETTLE_S = 30.0

# A single long Wait: the execution can only leave RUNNING because this check stops it.
_DEFINITION = {
    "Comment": "sim2real events-workload-state-change aborted-event",
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
    """Stopping one of two running executions produces an ABORTED event for exactly that one,
    after its RUNNING event, carrying the error and cause given to StopExecution; the sibling
    stays silent until it too is stopped."""
    sfn = ctx.client("stepfunctions")

    role_arn = _create_states_role(ctx)
    sm_arn = _create_state_machine(ctx, _xname(ctx, "sm")[:80], _DEFINITION, role_arn)
    queue = _create_queue(ctx)
    _rule_to_queue(
        ctx,
        {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE],
         "detail": {"stateMachineArn": [sm_arn], "status": ["RUNNING", "ABORTED"]}},
        queue,
    )

    launched: list[str] = []

    def _stop_all() -> None:
        for arn in launched:
            _best_effort(lambda a=arn: sfn.stop_execution(executionArn=a),
                         "ExecutionDoesNotExist", f"stop execution {arn}")

    ctx.on_cleanup(_stop_all)

    def _launch() -> str:
        arn = sfn.start_execution(
            stateMachineArn=sm_arn, name=_xname(ctx, "ex")[:80], input=json.dumps({"n": len(launched)})
        )["executionArn"]
        launched.append(arn)
        return arn

    sink: list[dict] = []

    def _events_for(arn: str, status: str) -> list[dict]:
        return [b for b in sink
                if b["detail"].get("executionArn") == arn and b["detail"].get("status") == status]

    # Launch pairs until one pair has BOTH RUNNING events observed (rule liveness is not instant).
    pair: tuple[str, str] | None = None
    t0 = time.monotonic()
    deadline = t0 + _EVENT_WAIT_S
    pairs = [(_launch(), _launch())]
    last_launch = t0
    while time.monotonic() < deadline and pair is None:
        _drain_once(ctx, queue["url"], sink)
        for x, y in pairs:
            if _events_for(x, "RUNNING") and _events_for(y, "RUNNING"):
                pair = (x, y)
                break
        if pair is None and time.monotonic() - last_launch > _RELAUNCH_EVERY_S:
            pairs.append((_launch(), _launch()))
            last_launch = time.monotonic()
    assert pair is not None, (
        f"within {_EVENT_WAIT_S:.0f}s no pair of running executions had both RUNNING events "
        f"delivered; received {len(sink)} event(s): {json.dumps(sink, default=str)[:600]}"
    )
    running_latency = time.monotonic() - t0
    target, sibling = pair

    running = _events_for(target, "RUNNING")[0]["detail"]
    for field in ("stopDate", "error", "cause", "output"):
        assert running[field] is None, (
            f"a RUNNING event must carry {field}=null, got {running[field]!r}"
        )
    assert running["redriveStatus"] == "NOT_REDRIVABLE", (
        f"a RUNNING execution cannot be redriven; got redriveStatus {running['redriveStatus']!r}"
    )

    token = ctx.unique_name("t")[-12:]
    stop_error = f"Sim2Real.OperatorStop.{token}"
    stop_cause = f"stopped by check {token} after RUNNING was observed"
    stopped = sfn.stop_execution(executionArn=target, error=stop_error, cause=stop_cause)
    assert "stopDate" in stopped, f"StopExecution must return a stopDate, got {stopped!r}"

    _poll_until(
        lambda: _drain_once(ctx, queue["url"], sink),
        lambda _s: bool(_events_for(target, "ABORTED")),
        timeout_s=_EVENT_WAIT_S,
        interval_s=0.5,
        description=f"an ABORTED status-change for the stopped execution {target}",
    )
    aborted_body = _events_for(target, "ABORTED")[0]
    aborted = aborted_body["detail"]
    described = sfn.describe_execution(executionArn=target)
    assert described["status"] == "ABORTED", (
        f"DescribeExecution must report ABORTED after StopExecution, got {described['status']!r}"
    )
    assert aborted_body["resources"] == [target], (
        f"envelope resources must be exactly the stopped execution, got {aborted_body['resources']!r}"
    )
    assert aborted["error"] == stop_error and aborted["cause"] == stop_cause, (
        f"the ABORTED event must carry StopExecution's error/cause "
        f"{(stop_error, stop_cause)!r}; got {(aborted.get('error'), aborted.get('cause'))!r}"
    )
    assert (described.get("error"), described.get("cause")) == (stop_error, stop_cause), (
        f"DescribeExecution must agree with the event: {(described.get('error'), described.get('cause'))!r}"
    )
    assert aborted["startDate"] == running["startDate"], (
        f"RUNNING and ABORTED events of one execution must share startDate: "
        f"{running['startDate']!r} vs {aborted['startDate']!r}"
    )
    assert isinstance(aborted["stopDate"], int) and aborted["stopDate"] >= aborted["startDate"], (
        f"ABORTED must carry an integer stopDate >= startDate, got {aborted['stopDate']!r}"
    )
    assert aborted["output"] is None, f"ABORTED output must be null, got {aborted['output']!r}"
    assert aborted["redriveStatus"] == described["redriveStatus"] == "REDRIVABLE", (
        f"an ABORTED Standard execution is redrivable: event {aborted.get('redriveStatus')!r}, "
        f"describe {described.get('redriveStatus')!r}"
    )

    # The sibling is still RUNNING: no ABORTED for it while the target's ABORTED has arrived.
    settle_until = time.monotonic() + max(_MIN_SETTLE_S, 2.0 * running_latency)
    while time.monotonic() < settle_until:
        _drain_once(ctx, queue["url"], sink)
    assert _events_for(sibling, "ABORTED") == [], (
        f"only {target} was stopped, yet an ABORTED event arrived for the sibling {sibling}"
    )
    assert sfn.describe_execution(executionArn=sibling)["status"] == "RUNNING", (
        "the sibling execution must still be RUNNING — it was never stopped"
    )

    # Repair: stop the sibling with NO error/cause; its ABORTED must now arrive, and its
    # error/cause must be whatever DescribeExecution says (not the target's strings).
    sfn.stop_execution(executionArn=sibling)
    _poll_until(
        lambda: _drain_once(ctx, queue["url"], sink),
        lambda _s: bool(_events_for(sibling, "ABORTED")),
        timeout_s=_EVENT_WAIT_S,
        interval_s=0.5,
        description=f"an ABORTED status-change for the sibling {sibling} once it is stopped",
    )
    sib = _events_for(sibling, "ABORTED")[0]["detail"]
    sib_described = sfn.describe_execution(executionArn=sibling)
    assert (sib["error"], sib["cause"]) == (sib_described.get("error"), sib_described.get("cause")), (
        f"sibling ABORTED event error/cause {(sib['error'], sib['cause'])!r} must equal "
        f"DescribeExecution {(sib_described.get('error'), sib_described.get('cause'))!r}"
    )
    assert sib["error"] != stop_error, (
        f"the sibling was stopped without an error, yet its event carries the target's {stop_error!r}"
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"
_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _now_ms() -> int:
    return int(time.time() * 1000)


def _best_effort(fn, gone_code: str, what: str) -> None:
    """Run a teardown call; an error other than gone_code is reported as a leak, never raised."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code != gone_code:
            raise RuntimeError(f"could not {what}: {code}") from exc


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
    """A role Step Functions can assume. Pass/Fail/Wait states need no permissions beyond that."""
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
        _best_effort(lambda: iam.delete_role(RoleName=n), "NoSuchEntity", f"delete role {n}")

    ctx.on_cleanup(_delete)
    return arn


def _create_state_machine(ctx, name: str, definition: dict, role_arn: str,
                          sm_type: str = "STANDARD") -> str:
    """Create the machine, retrying only through the IAM role-propagation window."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 90
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type=sm_type,
                tags=[{"key": k, "value": v} for k, v in _TAGS.items()],
            )["stateMachineArn"]
        except ClientError as exc:
            last = exc.response.get("Error", {}).get("Code")
            if last != "AccessDeniedException":
                raise
            time.sleep(3)
            continue

        def _delete(a=arn):
            _best_effort(lambda: sfn.delete_state_machine(stateMachineArn=a),
                         "StateMachineDoesNotExist", f"delete state machine {a}")

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
        _best_effort(lambda: events.remove_targets(Rule=n, Ids=["q"], Force=True),
                     "ResourceNotFoundException", f"remove target from rule {n}")
        _best_effort(lambda: events.delete_rule(Name=n, Force=True),
                     "ResourceNotFoundException", f"delete rule {n}")

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
