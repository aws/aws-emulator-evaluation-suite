"""events-workload-state-change-sfn-failed-event-carries-the-fail-states-runtime-error-and-cause."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

# AWS behavior: a Standard execution that ends in a Fail state whose ErrorPath/CausePath
# resolve against the execution input is delivered to the default bus as a
# "Step Functions Execution Status Change" with detail.status FAILED and detail.error /
# detail.cause equal to the RUNTIME strings, identical to what DescribeExecution reports;
# detail.output is null and detail.redriveStatus is "REDRIVABLE".

CHECK = "events-workload-state-change-sfn-failed-event-carries-the-fail-states-runtime-error-and-cause"
GROUP = "event-propagation"
SERVICES = ["events", "stepfunctions", "sqs"]

_SOURCE = "aws.states"
_DETAIL_TYPE = "Step Functions Execution Status Change"
_EVENT_WAIT_S = 240.0
_RELAUNCH_EVERY_S = 60.0
_MIN_SETTLE_S = 30.0
_CLOCK_SKEW_MS = 60_000

# The Fail state takes its error and cause from the INPUT, so the strings in the event cannot be
# a constant of the definition: two executions of the same machine must carry two different pairs.
_DEFINITION = {
    "Comment": "sim2real events-workload-state-change failed-event",
    "StartAt": "Prepare",
    "States": {
        "Prepare": {"Type": "Pass", "Next": "Explode"},
        "Explode": {"Type": "Fail", "ErrorPath": "$.error", "CausePath": "$.cause"},
    },
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
    """A FAILED Standard execution's status-change event carries the failing state's real,
    per-execution error and cause strings, and a rule that filters on detail.error routes only
    the execution that raised that error."""
    sfn = ctx.client("stepfunctions")
    account = ctx.client("sts").get_caller_identity()["Account"]

    role_arn = _create_states_role(ctx)
    sm_arn = _create_state_machine(ctx, _xname(ctx, "sm")[:80], _DEFINITION, role_arn)

    token = ctx.unique_name("t")[-12:]
    pairs = {
        "a": {"error": f"Sim2Real.AlphaFailure.{token}", "cause": f"alpha cause {token}: disk on fire"},
        "b": {"error": f"Sim2Real.BetaFailure.{token}", "cause": f"beta cause {token}: quota gone"},
    }

    q_all = _create_queue(ctx)
    q_alpha = _create_queue(ctx)
    _rule_to_queue(
        ctx,
        {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE],
         "detail": {"stateMachineArn": [sm_arn], "status": ["FAILED"]}},
        q_all,
    )
    _rule_to_queue(
        ctx,
        {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE],
         "detail": {"stateMachineArn": [sm_arn], "status": ["FAILED"],
                    "error": [pairs["a"]["error"]]}},
        q_alpha,
    )

    # One execution per pair; relaunched (fresh name, same pair) until the FAILED-status queue has
    # seen both kinds, because a rule on the default bus is not live the instant PutRule returns.
    launched: dict[str, list[str]] = {"a": [], "b": []}
    started_ms = _now_ms()

    def _launch(kind: str) -> None:
        launched[kind].append(
            sfn.start_execution(
                stateMachineArn=sm_arn,
                name=_xname(ctx, f"ex{kind}")[:80],
                input=json.dumps(pairs[kind]),
            )["executionArn"]
        )

    for kind in pairs:
        _launch(kind)

    all_sink: list[dict] = []
    t0 = time.monotonic()
    deadline = t0 + _EVENT_WAIT_S
    last_launch = t0
    seen: dict[str, dict] = {}
    while time.monotonic() < deadline and len(seen) < 2:
        _drain_once(ctx, q_all["url"], all_sink)
        for body in all_sink:
            arn = body["detail"].get("executionArn")
            for kind, arns in launched.items():
                if arn in arns and kind not in seen:
                    seen[kind] = body
        if len(seen) < 2 and time.monotonic() - last_launch > _RELAUNCH_EVERY_S:
            for kind in pairs:
                if kind not in seen:
                    _launch(kind)
            last_launch = time.monotonic()
    latency = time.monotonic() - t0
    assert set(seen) == {"a", "b"}, (
        f"within {_EVENT_WAIT_S:.0f}s the FAILED-status rule must deliver an event for both failing "
        f"executions; saw kinds {sorted(seen)!r} from {len(all_sink)} delivered event(s): "
        f"{json.dumps(all_sink, default=str)[:600]}"
    )
    observed_ms = _now_ms()

    for kind, body in seen.items():
        detail = body["detail"]
        exec_arn = detail["executionArn"]
        described = sfn.describe_execution(executionArn=exec_arn)
        assert described["status"] == "FAILED", (
            f"DescribeExecution must report FAILED for {exec_arn}, got {described['status']!r}"
        )
        assert body["source"] == _SOURCE and body["detail-type"] == _DETAIL_TYPE, (
            f"envelope must be ({_SOURCE!r}, {_DETAIL_TYPE!r}), got "
            f"({body.get('source')!r}, {body.get('detail-type')!r})"
        )
        assert body["account"] == account and body["region"] == ctx.region, (
            f"envelope must be attributed to {account!r}/{ctx.region!r}, got "
            f"{body.get('account')!r}/{body.get('region')!r}"
        )
        assert body["resources"] == [exec_arn], (
            f"envelope resources must be exactly the execution ARN, got {body.get('resources')!r}"
        )
        assert detail["status"] == "FAILED", f"detail.status must be FAILED, got {detail['status']!r}"
        assert detail["error"] == pairs[kind]["error"], (
            f"execution {kind}: detail.error must be the runtime error its Fail state resolved from "
            f"input, {pairs[kind]['error']!r}; got {detail.get('error')!r} (a generic or constant "
            f"error string is exactly the defect this check exists to catch)"
        )
        assert detail["cause"] == pairs[kind]["cause"], (
            f"execution {kind}: detail.cause must be {pairs[kind]['cause']!r}, got "
            f"{detail.get('cause')!r}"
        )
        assert (detail["error"], detail["cause"]) == (described["error"], described["cause"]), (
            f"the event's (error, cause) must equal DescribeExecution's: event "
            f"{(detail['error'], detail['cause'])!r}, describe "
            f"{(described.get('error'), described.get('cause'))!r}"
        )
        assert detail["output"] is None, (
            f"a FAILED execution has no output, so detail.output must be null; got {detail['output']!r}"
        )
        assert json.loads(detail["input"]) == pairs[kind], (
            f"detail.input must be the execution's input {pairs[kind]!r}, got {detail['input']!r}"
        )
        assert detail["redriveStatus"] == described["redriveStatus"] == "REDRIVABLE", (
            f"a FAILED Standard execution is redrivable: event redriveStatus "
            f"{detail.get('redriveStatus')!r}, describe {described.get('redriveStatus')!r}"
        )
        start_ms, stop_ms = detail["startDate"], detail["stopDate"]
        assert isinstance(start_ms, int) and isinstance(stop_ms, int), (
            f"startDate/stopDate must be integer epoch millis, got {start_ms!r}/{stop_ms!r}"
        )
        assert started_ms - _CLOCK_SKEW_MS <= start_ms <= stop_ms <= observed_ms + _CLOCK_SKEW_MS, (
            f"startDate <= stopDate must fall inside the measured window "
            f"[{started_ms - _CLOCK_SKEW_MS}, {observed_ms + _CLOCK_SKEW_MS}]; got "
            f"{start_ms}..{stop_ms}"
        )

    # The error-filtered rule: alpha arrives there, beta never does. Beta's event reached the
    # FAILED-status queue in this same run, so its absence here is about detail.error, not timing.
    alpha_sink: list[dict] = []
    _poll_until(
        lambda: _drain_once(ctx, q_alpha["url"], alpha_sink),
        lambda sink: any(b["detail"].get("executionArn") in launched["a"] for b in sink),
        timeout_s=_EVENT_WAIT_S,
        interval_s=0.5,
        description="the detail.error-filtered rule delivers the alpha execution's FAILED event",
    )
    settle_until = time.monotonic() + max(_MIN_SETTLE_S, 2.0 * latency)
    while time.monotonic() < settle_until:
        _drain_once(ctx, q_alpha["url"], alpha_sink)
    strays = [b for b in alpha_sink if b["detail"].get("error") != pairs["a"]["error"]]
    assert strays == [], (
        f"the rule pinned to detail.error {pairs['a']['error']!r} received {len(strays)} event(s) "
        f"carrying another error — the error field is not what the event was routed on: "
        f"{json.dumps([b['detail'].get('error') for b in strays])}"
    )
    beta_in_alpha = [b for b in alpha_sink if b["detail"].get("executionArn") in launched["b"]]
    assert beta_in_alpha == [], (
        f"the beta execution raised {pairs['b']['error']!r} yet reached the alpha-error rule"
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
