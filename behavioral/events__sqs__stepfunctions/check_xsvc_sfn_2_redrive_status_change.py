"""xsvc-sfn-2-redrive-status-change."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-sfn-2-redrive-status-change"
GROUP = "event-propagation"
SERVICES = ["events", "stepfunctions", "sqs"]

_SOURCE = "aws.states"
_DETAIL_TYPE = "Step Functions Execution Status Change"
_EVENT_WAIT_S = 150.0
_RELAUNCH_EVERY_S = 45.0


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "cap:c3",
)
def run(ctx) -> None:
    """A redriven Standard execution's status-change events carry the redrive: FAILED reads
    REDRIVABLE with redriveCount 0, then RUNNING and SUCCEEDED read redriveCount 1, RedriveExecution's
    redriveDate and the original startDate, and the redriven task re-runs against current state."""
    sfn = ctx.client("stepfunctions")
    sqs = ctx.client("sqs")

    work = _create_queue(ctx)
    role_arn = _create_role(
        ctx, "states.amazonaws.com",
        {"Effect": "Allow", "Action": "sqs:ReceiveMessage", "Resource": work["arn"]},
    )
    # The Take task fails with States.Runtime while the work queue is empty (no Messages[0]), and
    # succeeds once a message is there; a redrive restarts AT the failed state, so the redriven
    # run must re-call ReceiveMessage rather than replay the recorded failure.
    definition = {
        "Comment": "sim2real xsvc-sfn-2 redrive",
        "StartAt": "Take",
        "States": {"Take": {
            "Type": "Task", "Resource": "arn:aws:states:::aws-sdk:sqs:receiveMessage",
            "Parameters": {"QueueUrl": work["url"], "MaxNumberOfMessages": 1, "WaitTimeSeconds": 2},
            "ResultSelector": {"body.$": "$.Messages[0].Body"},
            "End": True,
        }},
    }
    sm_arn = _create_state_machine(ctx, _xname(ctx, "sm")[:80], definition, role_arn)

    q_events = _create_queue(ctx)
    _rule_to_queue(
        ctx, {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE], "detail": {"stateMachineArn": [sm_arn]}},
        q_events,
    )

    # Launch (relaunching while the rule is not yet live or the role not yet assumable) until the
    # bus has delivered a FAILED event whose failure is the empty-queue runtime error.
    sink: list[dict] = []
    launched: dict[str, dict] = {}
    t0 = time.monotonic()
    last = float("-inf")
    failed = None
    while time.monotonic() - t0 < _EVENT_WAIT_S and failed is None:
        if time.monotonic() - last > _RELAUNCH_EVERY_S:
            inp = {"attempt": len(launched), "token": ctx.unique_name("t")[-12:]}
            arn = sfn.start_execution(
                stateMachineArn=sm_arn, name=_xname(ctx, "ex")[:80], input=json.dumps(inp),
            )["executionArn"]
            launched[arn] = inp
            last = time.monotonic()
        _drain_once(ctx, q_events["url"], sink)
        for b in sink:
            d = b["detail"]
            if d["executionArn"] in launched and d["status"] == "FAILED" and d["error"] == "States.Runtime":
                failed = b
    assert failed is not None, (
        f"within {_EVENT_WAIT_S:.0f}s the bus must deliver a FAILED event with error States.Runtime for "
        f"one of {len(launched)} execution(s); delivered "
        f"{[(b['detail']['status'], b['detail'].get('error')) for b in sink]!r}"
    )
    exec_arn = failed["detail"]["executionArn"]
    fd = failed["detail"]
    assert (fd["redriveCount"], fd["redriveStatus"], fd["redriveDate"]) == (0, "REDRIVABLE", None), (
        f"the first run's FAILED event must read redriveCount 0, REDRIVABLE, redriveDate null; got "
        f"{(fd.get('redriveCount'), fd.get('redriveStatus'), fd.get('redriveDate'))!r}"
    )
    original_start = fd["startDate"]

    payload = f"work-{ctx.unique_name('w')[-12:]}"
    sqs.send_message(QueueUrl=work["url"], MessageBody=payload)
    redrive_ms = _epoch_ms(sfn.redrive_execution(executionArn=exec_arn)["redriveDate"])

    def _redriven(status: str):
        return [b for b in sink if b["detail"]["executionArn"] == exec_arn
                and b["detail"]["status"] == status and b["detail"]["redriveCount"] == 1]

    _poll_until(
        lambda: _drain_once(ctx, q_events["url"], sink),
        lambda _s: _redriven("RUNNING") and _redriven("SUCCEEDED"),
        timeout_s=_EVENT_WAIT_S, interval_s=0.5,
        description=f"the bus delivers RUNNING and SUCCEEDED events with redriveCount 1 for {exec_arn}",
    )
    running, succeeded = _redriven("RUNNING")[0]["detail"], _redriven("SUCCEEDED")[0]["detail"]

    for label, d in (("RUNNING", running), ("SUCCEEDED", succeeded)):
        assert d["redriveDate"] == redrive_ms, (
            f"the redriven {label} event's redriveDate must equal RedriveExecution's redriveDate "
            f"{redrive_ms}; got {d.get('redriveDate')!r}"
        )
        assert d["startDate"] == original_start, (
            f"a redrive keeps the execution's original startDate {original_start}; the {label} event "
            f"has {d.get('startDate')!r}"
        )
        assert d["redriveStatus"] == "NOT_REDRIVABLE", (
            f"the redriven {label} event must read NOT_REDRIVABLE; got {d.get('redriveStatus')!r}"
        )
        assert d["redriveStatusReason"] == f"Execution is {label} and cannot be redriven", (
            f"the redriven {label} event's redriveStatusReason; got {d.get('redriveStatusReason')!r}"
        )
    # Order on the events' own clocks (SUCCEEDED can be delivered before RUNNING): failure,
    # then redrive, then the redriven run's end.
    assert running["stopDate"] is None, f"a RUNNING event has no stopDate; got {running['stopDate']!r}"
    assert fd["stopDate"] <= redrive_ms <= succeeded["stopDate"], (
        f"FAILED.stopDate <= redriveDate <= SUCCEEDED.stopDate must hold; got "
        f"{fd['stopDate']} / {redrive_ms} / {succeeded.get('stopDate')}"
    )
    assert not _redriven("FAILED"), (
        f"the redriven run must not fail; got {[b['detail'].get('cause') for b in _redriven('FAILED')]!r}"
    )

    described = sfn.describe_execution(executionArn=exec_arn)
    assert (described["status"], described["redriveCount"]) == ("SUCCEEDED", 1), (
        f"DescribeExecution must agree with the events: SUCCEEDED, redriveCount 1; got "
        f"{(described['status'], described.get('redriveCount'))!r}"
    )
    assert json.loads(described["output"]) == {"body": payload}, (
        f"the redriven task must have re-run ReceiveMessage and taken {payload!r}; output "
        f"{described.get('output')!r}"
    )
    assert json.loads(succeeded["output"]) == {"body": payload}, (
        f"the SUCCEEDED event's output must be the redriven run's output; got {succeeded.get('output')!r}"
    )

    # A SUCCEEDED execution cannot be redriven again.
    refusal = _client_error(lambda: sfn.redrive_execution(executionArn=exec_arn))
    expected = (
        "ExecutionNotRedrivable",
        f"Execution {exec_arn} invalid for redrive as: Execution is SUCCEEDED and cannot be redriven",
    )
    assert refusal == expected, (
        f"redriving a SUCCEEDED execution must fail with {expected!r}; got {refusal!r}"
    )


def _epoch_ms(value) -> int:
    return int(round(value.timestamp() * 1000))


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
        _tolerate(lambda: iam.delete_role_policy(RoleName=n, PolicyName="inline"))
        _tolerate(lambda: iam.delete_role(RoleName=n), "NoSuchEntity", leak=f"could not delete role {n}")

    ctx.on_cleanup(_delete)
    iam.put_role_policy(
        RoleName=name, PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [statement]}),
    )
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
    ctx.client("events").put_targets(Rule=name, Targets=[{"Id": "q", "Arn": queue["arn"]}])
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
