"""execution-status-change-event-reaches-the-default-bus."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "execution-status-change-event-reaches-the-default-bus"
GROUP = 'eventing'
SERVICES = ['events', 'stepfunctions']

#: How long the delivered envelope may take to appear on the consumer queue.
_DELIVERY_BUDGET_S = 180.0

#: The delivery latency above which this check refuses to reason about an absence at all: a
#: window calibrated on a pathological measurement is not a calibrated window.
_MAX_CREDIBLE_DELIVERY_WAIT_S = 120.0

#: The floor for the absence window, and its ceiling. The window actually used is
#: max(floor, 3 x the measured positive-control latency), capped by the ceiling.
#: The `_BUDGET_S` suffix declares them as wall-clock budgets the suite is sized to fit.
_ABSENCE_FLOOR_BUDGET_S = 90.0
_ABSENCE_CEILING_BUDGET_S = 360.0

_SOURCE = "aws.states"
_DETAIL_TYPE = "Step Functions Execution Status Change"

#: A single Pass state. Load-bearing for the negative: a Pass state has no failure mode, so
#: `status: FAILED` is STRUCTURALLY unreachable for this machine — the twin rule's pattern cannot
#: be satisfied by construction, not merely by timing.
_DEFINITION = {
    "Comment": "sim2real-behav: terminal-status emission",
    "StartAt": "Done",
    "States": {
        "Done": {
            "Type": "Pass",
            "Result": {"marker": "sim2real-behav-states-emit", "n": 7},
            "End": True,
        }
    },
}


# ===== helpers =====
def _poll(probe, predicate, timeout_s, interval_s=3.0, what=""):
    """Bounded retry that RAISES on timeout. Never a bare sleep."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _queue(sqs, ctx, region: str, account: str) -> tuple[str, str]:
    """An SQS queue whose policy admits EventBridge rules on this account's DEFAULT bus.

    The SourceArn condition names `rule/*` and not `rule/<bus>/*`: a rule on the default bus has
    no bus segment in its ARN, which is exactly the shape a custom-bus check would get wrong.
    """
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-states-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowEventBridgeDefaultBusRules",
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": arn,
            "Condition": {"ArnLike": {"aws:SourceArn": f"arn:aws:events:{region}:{account}:rule/*"}},
        }],
    })})
    return url, arn


def _receive(sqs, url: str, wait: int = 5) -> list[dict]:
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait)
    msgs = resp.get("Messages", [])
    if msgs:
        sqs.delete_message_batch(QueueUrl=url, Entries=[
            {"Id": f"d{i}", "ReceiptHandle": m["ReceiptHandle"]} for i, m in enumerate(msgs)])
    return [json.loads(m["Body"]) for m in msgs]


def _collect_for(sqs, url: str, execution_arn: str, budget_s: float) -> list[dict]:
    """Every envelope on *url* whose detail names *execution_arn*, within *budget_s*."""
    got: list[dict] = []
    deadline = time.monotonic() + budget_s
    while time.monotonic() < deadline and not got:
        got += [e for e in _receive(sqs, url)
                if e.get("detail", {}).get("executionArn") == execution_arn]
    return got


def _drain_empty(sqs, url: str, budget_s: float = 60.0) -> None:
    empties = 0
    deadline = time.monotonic() + budget_s
    while time.monotonic() < deadline and empties < 2:
        empties = empties + 1 if not _receive(sqs, url, wait=2) else 0
    assert empties >= 2, f"queue {url!r} would not drain to empty inside {budget_s}s"


def _put_rule(ev, ctx, name: str, pattern: dict, queue_arn: str) -> None:
    ev.put_rule(Name=name, EventPattern=json.dumps(pattern), State="ENABLED",
                Description="sim2real-behav states->eventbridge",
                Tags=[{"Key": "sim2real", "Value": "states-status-change"}])
    ctx.on_cleanup(lambda: ev.delete_rule(Name=name))
    resp = ev.put_targets(Rule=name, Targets=[{"Id": "q", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: ev.remove_targets(Rule=name, Ids=["q"]))
    assert resp["FailedEntryCount"] == 0, (
        f"put_targets for rule {name!r} reported {resp['FailedEntryCount']} failures: "
        f"{resp.get('FailedEntries')!r}"
    )


def _pattern(state_machine_arn: str, status: str) -> dict:
    return {
        "source": [_SOURCE],
        "detail-type": [_DETAIL_TYPE],
        "detail": {"stateMachineArn": [state_machine_arn], "status": [status]},
    }


@tags("axis:negative-delivery", "cap:c4", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Standard execution's terminal transition is DELIVERED to a default-bus rule's queue as
    an `aws.states` / "Step Functions Execution Status Change" envelope whose detail agrees with
    DescribeExecution, while a twin rule differing only in its status predicate receives nothing.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/eventbridge-integration.html
    """
    ev = ctx.client("events")
    sqs = ctx.client("sqs")
    sfn = ctx.client("stepfunctions")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    # --- a role Step Functions can assume; a Pass-only machine needs no permissions ----------
    role_name = ctx.unique_name("sim2real-behav-states-emit-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
        Description="sim2real-behav states status-change emission",
        Tags=[{"Key": "sim2real", "Value": "states-status-change"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    # --- the two consumer queues, created BEFORE the state machine so no event is missed -----
    match_url, match_arn = _queue(sqs, ctx, ctx.region, account)
    twin_url, twin_arn = _queue(sqs, ctx, ctx.region, account)

    # --- the state machine ------------------------------------------------------------------
    sm_name = ctx.unique_name("sim2real-behav-states-emit-")
    sm_arn = _poll(
        lambda: _create_state_machine(sfn, sm_name, role_arn),
        lambda arn: arn is not None,
        timeout_s=60.0,
        what="CreateStateMachine accepting a freshly minted role (IAM propagation)",
    )
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    match_rule = f"{sm_name}-succeeded"
    twin_rule = f"{sm_name}-failed-twin"
    _put_rule(ev, ctx, match_rule, _pattern(sm_arn, "SUCCEEDED"), match_arn)
    _put_rule(ev, ctx, twin_rule, _pattern(sm_arn, "FAILED"), twin_arn)

    # Both rules must really own exactly their own queue, or neither result means anything.
    for rule, want in ((match_rule, match_arn), (twin_rule, twin_arn)):
        arns = [t["Arn"] for t in ev.list_targets_by_rule(Rule=rule)["Targets"]]
        assert arns == [want], (
            f"rule {rule!r} must target exactly {want!r}; list_targets_by_rule reports {arns!r}"
        )

    # --- drive the execution ----------------------------------------------------------------
    exec_name = ctx.unique_name("e-")
    started_at = time.monotonic()
    execution_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=exec_name, input=json.dumps({"probe": exec_name}),
    )["executionArn"]

    described = _poll(
        lambda: sfn.describe_execution(executionArn=execution_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=120.0,
        what=f"execution {exec_name!r} leaving RUNNING",
    )
    assert described["status"] == "SUCCEEDED", (
        f"a single Pass state must succeed; DescribeExecution reports {described['status']!r} "
        f"(error={described.get('error')!r} cause={described.get('cause')!r})"
    )

    # --- the terminal read, at the CONSUMER --------------------------------------------------
    envelopes = _collect_for(sqs, match_url, execution_arn, _DELIVERY_BUDGET_S)
    delivery_latency_s = time.monotonic() - started_at
    assert envelopes, (
        f"no envelope naming execution {execution_arn!r} reached the rule's queue within "
        f"{_DELIVERY_BUDGET_S}s; DescribeExecution says the execution is "
        f"{described['status']!r}, so the execution ran and the EMISSION is what is missing"
    )
    envelope = envelopes[0]
    detail = envelope["detail"]

    assert envelope["source"] == _SOURCE, (
        f"expected source {_SOURCE!r}, got {envelope['source']!r}"
    )
    assert envelope["detail-type"] == _DETAIL_TYPE, (
        f"expected detail-type {_DETAIL_TYPE!r}, got {envelope['detail-type']!r}"
    )
    assert detail["executionArn"] == execution_arn, (
        f"expected detail.executionArn {execution_arn!r}, got {detail.get('executionArn')!r}"
    )
    assert detail["stateMachineArn"] == sm_arn, (
        f"expected detail.stateMachineArn {sm_arn!r}, got {detail.get('stateMachineArn')!r}"
    )
    assert detail["name"] == exec_name, (
        f"expected detail.name {exec_name!r}, got {detail.get('name')!r}"
    )
    assert detail["status"] == described["status"], (
        f"the delivered status must equal the status DescribeExecution reports "
        f"({described['status']!r}); the envelope says {detail.get('status')!r}"
    )
    # Two independent readers of the same execution's output must agree. Derived, not a literal:
    # the expected value is _DEFINITION's Pass Result, and DescribeExecution is the second reader.
    assert json.loads(detail["output"]) == _DEFINITION["States"]["Done"]["Result"], (
        f"expected detail.output to parse to {_DEFINITION['States']['Done']['Result']!r}, got "
        f"{detail.get('output')!r}"
    )
    assert json.loads(detail["output"]) == json.loads(described["output"]), (
        f"the event's output {detail.get('output')!r} disagrees with DescribeExecution's "
        f"{described.get('output')!r}"
    )
    assert json.loads(detail["input"]) == {"probe": exec_name}, (
        f"expected detail.input to carry the execution input, got {detail.get('input')!r}"
    )
    assert isinstance(detail["startDate"], int) and isinstance(detail["stopDate"], int), (
        f"startDate/stopDate must be integers, got {detail.get('startDate')!r} / "
        f"{detail.get('stopDate')!r}"
    )
    assert detail["stopDate"] >= detail["startDate"], (
        f"stopDate {detail['stopDate']!r} precedes startDate {detail['startDate']!r}"
    )
    assert detail["outputDetails"]["included"] is True, (
        f"the output was inlined above, so outputDetails.included must be True, got "
        f"{detail.get('outputDetails')!r}"
    )

    # --- the absence, on wiring proven identical except for the status predicate --------------
    assert delivery_latency_s <= _MAX_CREDIBLE_DELIVERY_WAIT_S, (
        f"the positive control took {delivery_latency_s:.1f}s, above the "
        f"{_MAX_CREDIBLE_DELIVERY_WAIT_S}s this check is willing to calibrate an absence against; "
        f"refusing to report an absence rather than widening the window silently"
    )
    absence_s = min(max(_ABSENCE_FLOOR_BUDGET_S, 3.0 * delivery_latency_s),
                    _ABSENCE_CEILING_BUDGET_S)
    leaked = _collect_for(sqs, twin_url, execution_arn, absence_s)
    assert leaked == [], (
        f"the twin rule asks for detail.status FAILED, which one Pass state cannot reach, yet "
        f"{len(leaked)} envelope(s) arrived over {absence_s:.0f}s: {leaked[:1]!r}"
    )
    depth = sqs.get_queue_attributes(
        QueueUrl=twin_url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    assert depth == {"ApproximateNumberOfMessages": "0",
                     "ApproximateNumberOfMessagesNotVisible": "0"}, (
        f"the twin rule's queue reports {depth!r}, not empty"
    )

    # --- the twin's own positive control: same rule, same target, satisfiable predicate -------
    ev.put_rule(Name=twin_rule, EventPattern=json.dumps(_pattern(sm_arn, "SUCCEEDED")),
                State="ENABLED")
    arns = [t["Arn"] for t in ev.list_targets_by_rule(Rule=twin_rule)["Targets"]]
    assert arns == [twin_arn], (
        f"repointing the twin rule's pattern dropped its target ({arns!r}), so the control "
        f"below would be untestable"
    )
    _drain_empty(sqs, twin_url)
    second_name = ctx.unique_name("e2-")
    second_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=second_name, input=json.dumps({"probe": second_name}),
    )["executionArn"]
    control = _collect_for(sqs, twin_url, second_arn, _DELIVERY_BUDGET_S)
    assert control, (
        f"after the SAME twin rule and target were repointed at a satisfiable status predicate, "
        f"no envelope for {second_arn!r} arrived in {_DELIVERY_BUDGET_S}s — so the earlier zero "
        f"cannot be attributed to the predicate"
    )
    assert control[0]["detail"]["status"] == "SUCCEEDED", (
        f"the control envelope carries status {control[0]['detail'].get('status')!r}"
    )
    assert control[0]["detail"]["executionArn"] == second_arn, (
        f"the control envelope names {control[0]['detail'].get('executionArn')!r}, not the "
        f"second execution {second_arn!r}"
    )


def _create_state_machine(sfn, name: str, role_arn: str) -> str | None:
    """CreateStateMachine, or None while the freshly minted role is still propagating.

    Narrow by design: only the documented propagation refusal is retried, and it is retried by
    the caller's bounded `_poll`, which raises. Any other error propagates immediately.
    """
    from botocore.exceptions import ClientError
    try:
        return sfn.create_state_machine(
            name=name,
            definition=json.dumps(_DEFINITION),
            roleArn=role_arn,
            type="STANDARD",
            tags=[{"key": "sim2real", "value": "states-status-change"}],
        )["stateMachineArn"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "AccessDeniedException":
            return None
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
