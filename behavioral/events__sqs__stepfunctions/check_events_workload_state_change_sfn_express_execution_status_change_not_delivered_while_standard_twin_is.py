"""events-workload-state-change-sfn-express-execution-status-change-not-delivered-while-standard-twin-is."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

# AWS behavior: with one rule on the default bus matching every aws.states status-change for both
# machines, an EXPRESS execution (started asynchronously) produced NO event at all over a 120s
# window, while Standard executions in the same run produced RUNNING and terminal events.

CHECK = "events-workload-state-change-sfn-express-execution-status-change-not-delivered-while-standard-twin-is"
GROUP = "event-propagation"
SERVICES = ["events", "stepfunctions", "sqs"]

_SOURCE = "aws.states"
_DETAIL_TYPE = "Step Functions Execution Status Change"
_EVENT_WAIT_S = 240.0
_RELAUNCH_EVERY_S = 60.0
_MIN_SETTLE_S = 45.0

_DEFINITION = {
    "Comment": "sim2real events-workload-state-change express twin",
    "StartAt": "Echo",
    "States": {"Echo": {"Type": "Pass", "Parameters": {"echo.$": "$.probe"}, "End": True}},
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
    """Identical definitions, one EXPRESS and one STANDARD, behind one rule that matches any
    status for either: the Standard executions are delivered and the Express executions — which
    demonstrably ran and succeeded — never are."""
    sfn = ctx.client("stepfunctions")

    role_arn = _create_states_role(ctx)
    standard = _create_state_machine(ctx, _xname(ctx, "std")[:80], _DEFINITION, role_arn)
    express = _create_state_machine(ctx, _xname(ctx, "exp")[:80], _DEFINITION, role_arn, "EXPRESS")
    queue = _create_queue(ctx)
    _rule_to_queue(
        ctx,
        {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE],
         "detail": {"stateMachineArn": [standard, express]}},
        queue,
    )

    std_launched: list[str] = []
    sink: list[dict] = []

    def _run_express(n: int) -> None:
        """Run the Express twin synchronously so its success is PROVEN, and once asynchronously."""
        probe = f"x{n}"
        out = sfn.start_sync_execution(stateMachineArn=express, input=json.dumps({"probe": probe}))
        assert out["status"] == "SUCCEEDED" and json.loads(out["output"]) == {"echo": probe}, (
            f"the Express twin must run and succeed synchronously, got status {out.get('status')!r} "
            f"output {out.get('output')!r}"
        )
        sfn.start_execution(stateMachineArn=express, input=json.dumps({"probe": probe + "a"}))

    def _launch_standard(n: int) -> None:
        std_launched.append(sfn.start_execution(
            stateMachineArn=standard, name=_xname(ctx, "ex")[:80], input=json.dumps({"probe": f"s{n}"})
        )["executionArn"])

    def _std_terminal() -> list[dict]:
        return [b for b in sink if b["detail"].get("stateMachineArn") == standard
                and b["detail"].get("status") == "SUCCEEDED"]

    # Round 1: both twins run; wait for the Standard control to arrive (relaunching both if the
    # rule was not yet live) — that arrival is the barrier the Express absence is measured against.
    rounds = 0
    _run_express(rounds)
    _launch_standard(rounds)
    t0 = time.monotonic()
    deadline = t0 + _EVENT_WAIT_S
    last_launch = t0
    while time.monotonic() < deadline and not _std_terminal():
        _drain_once(ctx, queue["url"], sink)
        if not _std_terminal() and time.monotonic() - last_launch > _RELAUNCH_EVERY_S:
            rounds += 1
            _run_express(rounds)
            _launch_standard(rounds)
            last_launch = time.monotonic()
    assert _std_terminal(), (
        f"the Standard control's SUCCEEDED event never arrived within {_EVENT_WAIT_S:.0f}s, so no "
        f"absence here would mean anything; received {json.dumps(sink, default=str)[:400]}"
    )
    latency = time.monotonic() - t0

    # Round 2, after the rule is proven live: run both again and demand the NEW Standard event.
    rounds += 1
    before = len(_std_terminal())
    _run_express(rounds)
    _launch_standard(rounds)
    _poll_until(
        lambda: _drain_once(ctx, queue["url"], sink),
        lambda _s: len(_std_terminal()) > before,
        timeout_s=_EVENT_WAIT_S,
        interval_s=0.5,
        description="a second Standard SUCCEEDED event once the rule is known to be live",
    )
    settle_until = time.monotonic() + max(_MIN_SETTLE_S, 3.0 * latency)
    while time.monotonic() < settle_until:
        _drain_once(ctx, queue["url"], sink)

    express_events = [b for b in sink if b["detail"].get("stateMachineArn") == express]
    assert express_events == [], (
        f"{2 * (rounds + 1)} Express executions ran and succeeded, and {len(express_events)} "
        f"status-change event(s) for the Express machine arrived; Express workflows must not emit "
        f"them: {json.dumps([b['detail'].get('status') for b in express_events])}"
    )
    std_statuses = sorted({b["detail"]["status"] for b in sink if b["detail"].get("stateMachineArn") == standard})
    assert std_statuses == ["RUNNING", "SUCCEEDED"], (
        f"the Standard twin on the same rule must deliver RUNNING and SUCCEEDED, got {std_statuses!r}"
    )
    delivered = {b["detail"]["executionArn"] for b in _std_terminal()}
    assert delivered <= set(std_launched), (
        f"every Standard event must name an execution this check started: stray "
        f"{sorted(delivered - set(std_launched))!r}"
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
