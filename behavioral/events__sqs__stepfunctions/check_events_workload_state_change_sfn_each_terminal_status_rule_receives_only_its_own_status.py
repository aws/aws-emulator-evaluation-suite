"""events-workload-state-change-sfn-each-terminal-status-rule-receives-only-its-own-status."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

# AWS behavior: SUCCEEDED, FAILED, ABORTED and TIMED_OUT executions each emit a status-change
# whose detail.status is that exact terminal status (a TIMED_OUT execution is NOT reported as
# FAILED), with error/cause equal to what DescribeExecution reports (null for SUCCEEDED and
# TIMED_OUT).

CHECK = "events-workload-state-change-sfn-each-terminal-status-rule-receives-only-its-own-status"
GROUP = "event-propagation"
SERVICES = ["events", "stepfunctions", "sqs"]

_SOURCE = "aws.states"
_DETAIL_TYPE = "Step Functions Execution Status Change"
_EVENT_WAIT_S = 240.0
_RELAUNCH_EVERY_S = 60.0
_MIN_SETTLE_S = 30.0
_STATUSES = ("SUCCEEDED", "FAILED", "ABORTED", "TIMED_OUT")

_ROUTER = {
    "Comment": "sim2real events-workload-state-change terminal-status router",
    "StartAt": "Route",
    "States": {
        "Route": {
            "Type": "Choice",
            "Choices": [
                {"Variable": "$.mode", "StringEquals": "ok", "Next": "Ok"},
                {"Variable": "$.mode", "StringEquals": "fail", "Next": "Boom"},
            ],
            "Default": "Hold",
        },
        "Ok": {"Type": "Pass", "Result": {"done": True}, "End": True},
        "Boom": {"Type": "Fail", "ErrorPath": "$.error", "CausePath": "$.cause"},
        "Hold": {"Type": "Wait", "Seconds": 600, "End": True},
    },
}
# A machine-level TimeoutSeconds shorter than its only Wait: the one way to reach TIMED_OUT.
_TIMEOUTER = {
    "Comment": "sim2real events-workload-state-change timeout",
    "TimeoutSeconds": 3,
    "StartAt": "Hold",
    "States": {"Hold": {"Type": "Wait", "Seconds": 120, "End": True}},
}


@tags(
    "axis:negative-delivery",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Four rules on the default bus, one per terminal status, and four executions driven to
    SUCCEEDED, FAILED, ABORTED and TIMED_OUT: each rule receives its own execution and nothing
    else, and each event's detail agrees with DescribeExecution."""
    sfn = ctx.client("stepfunctions")

    role_arn = _create_states_role(ctx)
    router = _create_state_machine(ctx, _xname(ctx, "sm")[:80], _ROUTER, role_arn)
    timeouter = _create_state_machine(ctx, _xname(ctx, "smto")[:80], _TIMEOUTER, role_arn)

    queues: dict[str, dict] = {}
    for status in _STATUSES:
        queues[status] = _create_queue(ctx)
        _rule_to_queue(
            ctx,
            {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE],
             "detail": {"stateMachineArn": [router, timeouter], "status": [status]}},
            queues[status],
        )

    token = ctx.unique_name("t")[-12:]
    fail_error, fail_cause = f"Sim2Real.Matrix.{token}", f"matrix failure {token}"
    launched: dict[str, list[str]] = {s: [] for s in _STATUSES}

    def _stop_all() -> None:
        for arn in launched["ABORTED"] + launched["TIMED_OUT"]:
            _tolerate(lambda a=arn: sfn.stop_execution(executionArn=a), "ExecutionDoesNotExist", leak=f"could not stop execution {arn}")

    ctx.on_cleanup(_stop_all)

    def _launch(status: str) -> None:
        name = _xname(ctx, status[:2].lower())[:80]
        if status == "TIMED_OUT":
            arn = sfn.start_execution(stateMachineArn=timeouter, name=name)["executionArn"]
        else:
            mode = {"SUCCEEDED": "ok", "FAILED": "fail", "ABORTED": "hold"}[status]
            arn = sfn.start_execution(
                stateMachineArn=router, name=name,
                input=json.dumps({"mode": mode, "error": fail_error, "cause": fail_cause}),
            )["executionArn"]
        launched[status].append(arn)
        if status == "ABORTED":
            sfn.stop_execution(executionArn=arn, error=f"Sim2Real.Stop.{token}", cause="matrix stop")

    for status in _STATUSES:
        _launch(status)

    sinks: dict[str, list[dict]] = {s: [] for s in _STATUSES}

    def _own(status: str) -> list[dict]:
        return [b for b in sinks[status] if b["detail"].get("executionArn") in launched[status]]

    t0 = time.monotonic()
    deadline = t0 + _EVENT_WAIT_S
    last_launch = t0
    while time.monotonic() < deadline and not all(_own(s) for s in _STATUSES):
        for status in _STATUSES:
            _drain_once(ctx, queues[status]["url"], sinks[status])
        if time.monotonic() - last_launch > _RELAUNCH_EVERY_S:
            for status in _STATUSES:
                if not _own(status):
                    _launch(status)
            last_launch = time.monotonic()
    latency = time.monotonic() - t0
    missing = [s for s in _STATUSES if not _own(s)]
    assert not missing, (
        f"within {_EVENT_WAIT_S:.0f}s every per-status rule must receive its own execution's event; "
        f"missing {missing!r}; per-queue statuses received: "
        f"{ {s: [b['detail'].get('status') for b in sinks[s]] for s in _STATUSES}!r}"
    )

    # Every queue has now delivered. Keep draining all four for a window scaled to the measured
    # latency, so a mis-routed event that travels as fast as the correct ones has time to land.
    settle_until = time.monotonic() + max(_MIN_SETTLE_S, 2.0 * latency)
    while time.monotonic() < settle_until:
        for status in _STATUSES:
            _drain_once(ctx, queues[status]["url"], sinks[status])

    all_launched = {arn: s for s, arns in launched.items() for arn in arns}
    for status in _STATUSES:
        wrong = [(all_launched.get(b["detail"].get("executionArn"), "foreign"), b["detail"].get("status"))
                 for b in sinks[status] if b["detail"].get("executionArn") not in launched[status]
                 or b["detail"].get("status") != status]
        assert wrong == [], (
            f"the rule filtered to detail.status {status!r} received events belonging to other "
            f"outcomes (driven-as, delivered-status): {wrong!r} — the status field is not being "
            f"evaluated, or the target reported the wrong terminal status"
        )

    for status in _STATUSES:
        detail = _own(status)[0]["detail"]
        described = sfn.describe_execution(executionArn=detail["executionArn"])
        assert described["status"] == status, (
            f"the execution driven to {status} is {described['status']!r} per DescribeExecution"
        )
        assert (detail["error"], detail["cause"]) == (described.get("error"), described.get("cause")), (
            f"{status}: event (error, cause) {(detail['error'], detail['cause'])!r} must equal "
            f"DescribeExecution {(described.get('error'), described.get('cause'))!r}"
        )
        assert isinstance(detail["stopDate"], int) and detail["stopDate"] >= detail["startDate"], (
            f"{status}: a terminal event must carry integer stopDate >= startDate, got "
            f"{detail['startDate']!r}..{detail['stopDate']!r}"
        )
    assert json.loads(_own("SUCCEEDED")[0]["detail"]["output"]) == {"done": True}, (
        f"the SUCCEEDED event must carry the Pass state's output, got "
        f"{_own('SUCCEEDED')[0]['detail']['output']!r}"
    )
    assert _own("FAILED")[0]["detail"]["error"] == fail_error, (
        f"the FAILED event must carry the Fail state's runtime error {fail_error!r}, got "
        f"{_own('FAILED')[0]['detail']['error']!r}"
    )
    assert _own("ABORTED")[0]["detail"]["error"] == f"Sim2Real.Stop.{token}", (
        f"the ABORTED event must carry StopExecution's error, got "
        f"{_own('ABORTED')[0]['detail']['error']!r}"
    )
    assert _own("TIMED_OUT")[0]["detail"]["stateMachineArn"] == timeouter, (
        "the TIMED_OUT event must come from the machine with TimeoutSeconds"
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"
_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _now_ms() -> int:
    return int(time.time() * 1000)


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
        _tolerate(lambda: iam.delete_role(RoleName=n), "NoSuchEntity", leak=f"could not delete role {n}")

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


def _rule_to_queue(ctx, pattern: dict, queue: dict) -> str:
    """A rule on the DEFAULT bus (where AWS service events land) with this queue as sole target."""
    events = ctx.client("events")
    name = _xname(ctx, "rule")[:64]
    arn = events.put_rule(
        Name=name, EventPattern=json.dumps(pattern),
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["RuleArn"]

    def _teardown(n=name):
        _tolerate(lambda: events.remove_targets(Rule=n, Ids=["q"], Force=True), "ResourceNotFoundException", leak=f"could not remove target from rule {n}")
        _tolerate(lambda: events.delete_rule(Name=n, Force=True), "ResourceNotFoundException", leak=f"could not delete rule {n}")

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
