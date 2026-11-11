"""redrive-of-running-execution-rejected-no-status-change-event-follows."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redrive-of-running-execution-rejected-no-status-change-event-follows"
GROUP = "event-propagation"
SERVICES = ["events", "sqs", "stepfunctions"]

_SOURCE = "aws.states"
_DETAIL_TYPE = "Step Functions Execution Status Change"
_EVENT_WAIT_S = 240.0
_RELAUNCH_EVERY_S = 60.0

# A single long Wait: the execution only leaves RUNNING because this check stops it.
_DEFINITION = {
    "Comment": "sim2real redrive-of-running-execution-rejected",
    "StartAt": "Hold",
    "States": {"Hold": {"Type": "Wait", "Seconds": 600, "End": True}},
}


@tags(
    "axis:rejection",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """RedriveExecution on a RUNNING execution is rejected with ExecutionNotRedrivable, and
    no redriven status-change event ever follows it on the default bus."""
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
    launched_at: dict[str, float] = {}

    def _stop_all() -> None:
        for arn in launched:
            _tolerate(lambda a=arn: sfn.stop_execution(executionArn=a), "ExecutionDoesNotExist",
                      leak=f"could not stop execution {arn}")

    ctx.on_cleanup(_stop_all)

    def _running(arn: str) -> list[dict]:
        return [b for b in sink
                if b["detail"].get("executionArn") == arn and b["detail"].get("status") == "RUNNING"]

    t0 = time.monotonic()
    deadline = t0 + _EVENT_WAIT_S
    last_launch = float("-inf")
    exec_arn = None
    while time.monotonic() < deadline and exec_arn is None:
        if time.monotonic() - last_launch > _RELAUNCH_EVERY_S:
            arn = sfn.start_execution(stateMachineArn=sm_arn, name=_xname(ctx, "ex")[:80],
                                      input=json.dumps({"attempt": len(launched)}))["executionArn"]
            launched.append(arn)
            last_launch = time.monotonic()
            launched_at[arn] = last_launch
        _drain_once(ctx, queue["url"], sink)
        for arn in launched:
            if _running(arn):
                exec_arn = arn
                break
    assert exec_arn is not None, (
        f"within {_EVENT_WAIT_S:.0f}s the bus never delivered a RUNNING event for any of "
        f"{len(launched)} launched execution(s) — the positive control for this negative check"
    )
    # Delivery latency of the found execution's own RUNNING event, from its StartExecution to
    # its arrival in the queue; the time spent before the rule began delivering is excluded.
    latency_s = time.monotonic() - launched_at[exec_arn]

    expected = (
        "ExecutionNotRedrivable",
        f"Execution {exec_arn} invalid for redrive as: Execution is RUNNING and cannot be redriven",
    )
    refusal = _client_error(lambda: sfn.redrive_execution(executionArn=exec_arn))
    assert refusal == expected, f"redriving a RUNNING execution must fail with {expected!r}; got {refusal!r}"

    # Hold over a window derived from the positive control's measured latency: no redriven
    # RUNNING, and no ABORTED, event ever follows the refused call.
    window = max(10.0, 3.0 * latency_s)
    hold_until = time.monotonic() + window
    while time.monotonic() < hold_until:
        _drain_once(ctx, queue["url"], sink)
    bad = [b["detail"] for b in sink if b["detail"].get("executionArn") == exec_arn
           and (b["detail"]["status"] == "ABORTED" or b["detail"].get("redriveCount") == 1)]
    assert bad == [], (
        f"the refused RedriveExecution must have no effect, yet the bus delivered {bad!r}"
    )

    described = sfn.describe_execution(executionArn=exec_arn)
    assert (described["status"], described["redriveCount"]) == ("RUNNING", 0), (
        f"DescribeExecution must still show RUNNING, redriveCount 0; got "
        f"{(described['status'], described.get('redriveCount'))!r}"
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"
_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _client_error(fn) -> tuple[str, str]:
    """(error code, message) of a call expected to fail; RAISES if the call succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"the call was expected to be refused but succeeded: {resp!r}")


def _tolerate(fn, *tolerated: str, leak: str = "") -> None:
    """Run a teardown call. With a leak label, an error code outside `tolerated` is reported as a
    leak; without one, a refused teardown call is ignored."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if leak and code not in tolerated:
            raise RuntimeError(f"{leak}: {code}") from exc


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
