"""step-functions-execution-status-change-reaches-the-default-bus."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Step Functions delivers status-change events to the default bus BEST EFFORT
# (https://docs.aws.amazon.com/eventbridge/latest/ref/events-ref-states.html), so each liveness
# attempt starts a fresh execution.

CHECK = "step-functions-execution-status-change-reaches-the-default-bus"
GROUP = "event-propagation"
SERVICES = ["events", "stepfunctions", "sqs"]

_DETAIL_TYPE = "Step Functions Execution Status Change"
_SOURCE = "aws.states"
_LIVENESS_TIMEOUT_S = 150.0
_ROLE_PROPAGATION_S = 60.0
_EXECUTION_TERMINAL_S = 60.0
_MIN_ABSENCE_WINDOW_S = 45.0
# Local-versus-AWS clock skew tolerance for the two-sided startDate/stopDate bracket. Generous on
# purpose: the bracket exists to establish the UNIT and the ordering, not to measure latency, and a
# tolerance of 60s is still ~1000x tighter than the seconds-versus-milliseconds question it settles.
_CLOCK_SKEW_MS = 60_000
_DEFINITION = {
    "Comment": "sim2real step-functions-execution-status-change-reaches-the-default-bus",
    "StartAt": "Passthrough",
    "States": {"Passthrough": {"Type": "Pass", "Result": {"ok": True, "n": 7}, "End": True}},
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
    """A Step Functions execution that succeeds is observed as an aws.states status-change event on the
    default bus, matched by a rule filtered on its own state machine ARN and status, and not by the
    otherwise identical rule filtered on a status it never reached."""
    events = ctx.client("events")
    sfn = ctx.client("stepfunctions")
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    role_arn = _create_states_role(ctx)
    machine_name = _xname(ctx, "sm")[:80]
    sm_arn = _create_state_machine(ctx, machine_name, role_arn)

    queue_succeeded = _create_queue(ctx)
    queue_failed = _create_queue(ctx)

    # Two rules on the DEFAULT bus, created together, identical except for the status they admit.
    rule_succeeded = _put_rule_with_sqs_target(ctx, _status_pattern(sm_arn, "SUCCEEDED"), queue_succeeded)
    rule_failed = _put_rule_with_sqs_target(ctx, _status_pattern(sm_arn, "FAILED"), queue_failed)

    # --- positive control and the measured subject in one loop. A rule on the default bus is not
    # live the instant PutRule returns, and Step Functions delivery is best-effort, so a fresh
    # execution is started per attempt until one of them is observed downstream. ---
    landed = _start_until_observed(ctx, sm_arn, queue_succeeded["url"])
    exec_arn = landed["execution_arn"]
    exec_name = landed["execution_name"]
    body = landed["body"]
    latency = landed["latency_s"]

    # The producer really did succeed — established BEFORE the consumer assertions, so the terminal
    # assertion of this check remains the one at the consumer.
    described = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"),
        timeout_s=_EXECUTION_TERMINAL_S,
        interval_s=2.0,
        description=f"execution {exec_name} reaches a terminal status",
    )
    assert described["status"] == "SUCCEEDED", (
        f"a Pass-only state machine must succeed; DescribeExecution reports "
        f"{described['status']!r} for {exec_arn}"
    )

    # --- the envelope, at the consumer. ---
    assert body.get("source") == _SOURCE, (
        f"the status-change event must carry source {_SOURCE!r}, got {body.get('source')!r}"
    )
    assert body.get("detail-type") == _DETAIL_TYPE, (
        f"the status-change event must carry detail-type {_DETAIL_TYPE!r}, got "
        f"{body.get('detail-type')!r}"
    )
    assert body.get("account") == account, (
        f"the event must be attributed to the executing account {account!r}, got "
        f"{body.get('account')!r}"
    )
    assert body.get("region") == ctx.region, (
        f"the event must be attributed to region {ctx.region!r}, got {body.get('region')!r}"
    )
    assert exec_arn in (body.get("resources") or []), (
        f"the envelope's resources array must name the execution: expected {exec_arn!r} in "
        f"{body.get('resources')!r}"
    )

    detail = body.get("detail") or {}
    assert detail.get("executionArn") == exec_arn, (
        f"detail.executionArn must be the ARN StartExecution returned: expected {exec_arn!r}, got "
        f"{detail.get('executionArn')!r} — this value comes from the live call, so no recorded "
        f"transcript can supply it"
    )
    assert detail.get("stateMachineArn") == sm_arn, (
        f"detail.stateMachineArn must be the ARN CreateStateMachine returned: expected {sm_arn!r}, "
        f"got {detail.get('stateMachineArn')!r}"
    )
    assert detail.get("name") == exec_name, (
        f"detail.name must be the execution name this check chose: expected {exec_name!r}, got "
        f"{detail.get('name')!r}"
    )
    assert detail.get("status") == "SUCCEEDED", (
        f"the rule admitted only status SUCCEEDED, so the delivered detail.status must be SUCCEEDED, "
        f"got {detail.get('status')!r} — a delivered event whose status disagrees with the pattern "
        f"that matched it means the status filter is not being evaluated"
    )

    # --- two-sided clock. The bracket also settles the undocumented unit. ---
    start_ms, stop_ms = detail.get("startDate"), detail.get("stopDate")
    assert isinstance(start_ms, int) and isinstance(stop_ms, int), (
        f"startDate and stopDate must be integers, got {start_ms!r} ({type(start_ms).__name__}) and "
        f"{stop_ms!r} ({type(stop_ms).__name__})"
    )
    lower = landed["started_at_ms"] - _CLOCK_SKEW_MS
    upper = landed["observed_at_ms"] + _CLOCK_SKEW_MS
    assert lower <= start_ms <= stop_ms <= upper, (
        f"startDate and stopDate must be epoch MILLISECONDS inside the measured execution window and "
        f"in order: got startDate={start_ms} stopDate={stop_ms}, window "
        f"[{lower}, {upper}] (StartExecution at {landed['started_at_ms']}, event observed at "
        f"{landed['observed_at_ms']}, {_CLOCK_SKEW_MS}ms skew allowance). A seconds-epoch value is "
        f"about a thousand times too small to fall in this window"
    )

    # --- the Pass state's result rode along in the event. ---
    assert json.loads(detail["output"]) == _DEFINITION["States"]["Passthrough"]["Result"], (
        f"detail.output must be the Pass state's result: expected "
        f"{_DEFINITION['States']['Passthrough']['Result']}, got {detail.get('output')!r}"
    )
    assert (detail.get("outputDetails") or {}).get("included") is True, (
        f"a two-key output is small enough to be inlined, so outputDetails.included must be true, got "
        f"{detail.get('outputDetails')!r}"
    )

    # --- the FAILED twin admitted nothing, on the same wiring, in the same run. ---
    window = max(_MIN_ABSENCE_WINDOW_S, 3.0 * latency)
    leaked = _drain(ctx, queue_failed["url"], window_s=window)
    assert leaked == [], (
        f"the rule filtered to status FAILED received {len(leaked)} event(s) even though no execution "
        f"of {sm_arn} ever failed — the status filter in the event pattern is not being evaluated. "
        f"Window was {window:.0f}s = 3x the measured SUCCEEDED latency of {latency:.1f}s. Bodies: "
        f"{json.dumps(leaked, default=str)[:300]}"
    )
    depth = sqs.get_queue_attributes(
        QueueUrl=queue_failed["url"], AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]["ApproximateNumberOfMessages"]
    assert depth == "0", (
        f"second observable disagrees with the empty drain: the FAILED-status queue reports "
        f"ApproximateNumberOfMessages={depth!r}, expected '0'"
    )
    # Both rules exist and both were wired the same way, so the silence above is about the pattern.
    assert events.list_targets_by_rule(Rule=rule_failed["name"]).get("Targets"), (
        f"rule {rule_failed['name']} must still have its SQS target attached, otherwise its silence "
        f"proves nothing about the status filter"
    )
    assert events.list_targets_by_rule(Rule=rule_succeeded["name"]).get("Targets"), (
        f"rule {rule_succeeded['name']} must still have its SQS target attached"
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _status_pattern(state_machine_arn: str, status: str) -> dict:
    """The status-change pattern, scoped to THIS state machine so nothing else in the account matches."""
    return {
        "source": [_SOURCE],
        "detail-type": [_DETAIL_TYPE],
        "detail": {"stateMachineArn": [state_machine_arn], "status": [status]},
    }


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
    """A role Step Functions can assume. A Pass-only machine needs no permissions beyond that."""
    iam = ctx.client("iam")
    name = _xname(ctx, "role")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_xsvc_tags_kv()
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda n=name: _delete_role(ctx, n))
    return arn


def _delete_role(ctx, name: str) -> None:
    iam = ctx.client("iam")
    try:
        for policy in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=name, PolicyName=policy)
        for attached in iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=name, PolicyArn=attached["PolicyArn"])
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise RuntimeError(f"could not delete role {name}: {exc}") from exc


def _create_state_machine(ctx, name: str, role_arn: str) -> str:
    """Create the state machine, retrying through the IAM role-propagation window."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + _ROLE_PROPAGATION_S
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(_DEFINITION),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": k, "value": v} for k, v in _xsvc_resource_tags().items()],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda a=arn: _delete_state_machine(ctx, a))
            return arn
        except ClientError as exc:
            last = exc.response.get("Error", {}).get("Code")
            if last not in ("AccessDeniedException", "InvalidArn", "ValidationException"):
                raise
            time.sleep(3)
    raise AssertionError(
        f"CreateStateMachine({name}) never succeeded within the {_ROLE_PROPAGATION_S}s IAM "
        f"role-propagation window; last error code was {last!r}"
    )


def _delete_state_machine(ctx, arn: str) -> None:
    _tolerate(lambda: ctx.client("stepfunctions").delete_state_machine(stateMachineArn=arn), "StateMachineDoesNotExist", "ResourceNotFoundException", leak=f"could not delete state machine {arn}")


def _create_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = _xname(ctx, "q")
    url = sqs.create_queue(QueueName=name, tags=_xsvc_resource_tags())["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"name": name, "url": url, "arn": arn}


def _put_rule_with_sqs_target(ctx, pattern: dict, queue: dict) -> dict[str, str]:
    """A rule on the DEFAULT event bus (which is where AWS service events land) with one SQS target."""
    events = ctx.client("events")
    name = _xname(ctx, "rule")
    arn = events.put_rule(Name=name, EventPattern=json.dumps(pattern), Tags=_xsvc_tags_kv())["RuleArn"]

    def _teardown(n=name):
        ev = ctx.client("events")
        _tolerate(lambda: ev.remove_targets(Rule=n, Ids=["t1"]), "ResourceNotFoundException", leak=f"could not remove target t1 from rule {n}")
        _tolerate(lambda: ev.delete_rule(Name=n, Force=True), "ResourceNotFoundException", leak=f"could not delete rule {n}")

    ctx.on_cleanup(_teardown)
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue["url"],
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowEventsSend",
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": queue["arn"],
                            "Condition": {"ArnEquals": {"aws:SourceArn": arn}},
                        }
                    ],
                }
            )
        },
    )
    events.put_targets(Rule=name, Targets=[{"Id": "t1", "Arn": queue["arn"]}])
    return {"name": name, "arn": arn}


def _body(msg: dict):
    raw = msg.get("Body", "")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw


def _drain(ctx, queue_url: str, *, window_s: float, max_total: int = 25) -> list:
    """Long-poll for window_s and return every parsed body seen, deleting as it goes.

    This is the NEGATIVE observable. Its emptiness only means something because the SUCCEEDED leg has
    already been observed on the same wiring in the same run.
    """
    sqs = ctx.client("sqs")
    seen: list = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline and len(seen) < max_total:
        wait = min(5, max(1, int(deadline - time.monotonic())))
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait)
        for msg in resp.get("Messages", []):
            seen.append(_body(msg))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return seen


def _start_until_observed(ctx, sm_arn: str, queue_url: str) -> dict[str, Any]:
    """Start a fresh execution per attempt until its status-change event is observed downstream.

    Re-starting is required, not optional, for two independent reasons: a rule on the default bus is
    not live the instant PutRule returns, and Step Functions status-change delivery is documented as
    BEST EFFORT, so any individual event may simply never arrive. Each attempt uses a unique
    execution name, so the returned envelope is matched to the execution that produced it by ARN
    rather than by timing. RAISES on timeout — this is the positive control and there is no skip.
    """
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + _LIVENESS_TIMEOUT_S
    attempts = 0
    strangers: list = []
    while time.monotonic() < deadline:
        attempts += 1
        exec_name = _xname(ctx, f"ex{attempts}")[:80]
        started_at_ms = _now_ms()
        sent_at = time.monotonic()
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn, name=exec_name, input=json.dumps({"attempt": attempts})
        )["executionArn"]
        for body in _drain(ctx, queue_url, window_s=15.0):
            if isinstance(body, dict) and (body.get("detail") or {}).get("executionArn") == exec_arn:
                return {
                    "execution_arn": exec_arn,
                    "execution_name": exec_name,
                    "body": body,
                    "latency_s": max(time.monotonic() - sent_at, 0.001),
                    "started_at_ms": started_at_ms,
                    "observed_at_ms": _now_ms(),
                }
            strangers.append(body)
    raise AssertionError(
        f"no 'Step Functions Execution Status Change' event for state machine {sm_arn} reached "
        f"{queue_url} after {attempts} executions over {_LIVENESS_TIMEOUT_S}s. Either Step Functions "
        f"is not publishing to the default bus at all, or the rule never matched. Other bodies seen: "
        f"{json.dumps(strangers, default=str)[:300]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
