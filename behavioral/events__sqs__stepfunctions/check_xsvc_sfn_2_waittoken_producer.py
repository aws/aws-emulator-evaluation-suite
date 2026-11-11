"""xsvc-sfn-2-waittoken-producer."""

from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-sfn-2-waittoken-producer"
GROUP = "event-propagation"
SERVICES = ["events", "stepfunctions", "sqs"]

_SOURCE = "sim.sfn"
_DETAIL_TYPE = "task.requested"
_MISMATCH_DETAIL_TYPE = "task.requested.x"
_EXEC_ATTEMPT_S = 75.0
_EXEC_BUDGET_S = 200.0
_DRAIN_EXTRA = 3

# The Lambda worker: reads the token out of the event the state machine PUBLISHED, and hands back
# a payload that is a function of that event (its id, its detail-type and the per-launch job id),
# so the execution's output can only equal it if the token travelled SFN -> EventBridge -> Lambda.
# The bounded AccessDenied retry is the IAM-propagation guard at first use of the role's
# permission: a single async invoke does not self-heal.
_WORKER_SRC = '''
import json, time
import boto3
from botocore.exceptions import ClientError

_sfn = boto3.client("stepfunctions")


def handler(event, context):
    detail = event["detail"]
    out = {
        "worker": "sim2real-xsvc-worker",
        "job": detail["job"],
        "eventId": event["id"],
        "detailType": event["detail-type"],
        "source": event["source"],
    }
    deadline = time.time() + 60
    while True:
        try:
            _sfn.send_task_success(taskToken=detail["taskToken"],
                                   output=json.dumps(out, sort_keys=True))
            return out
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.time() > deadline:
                raise
            time.sleep(3)
'''


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
    """A state machine publishes an event through events:putEvents.waitForTaskToken, a rule routes
    it to a Lambda worker that calls SendTaskSuccess, and the execution's output is exactly the
    worker's payload; a sibling rule on detail-type "task.requested.x" receives nothing."""
    sfn = ctx.client("stepfunctions")
    events = ctx.client("events")
    account = ctx.client("sts").get_caller_identity()["Account"]
    nonce = ctx.unique_name("n")[-12:]

    bus_name, bus_arn = _create_bus(ctx)

    q_ctrl = _create_queue(ctx)
    q_mismatch = _create_queue(ctx)

    # The mismatched rule is created FIRST, so it is at least as live as the matching rule by the
    # time the matching side delivers: its silence then cannot be a rule that was not yet active.
    mismatch_rule = _create_rule(
        ctx, bus_name,
        {"source": [_SOURCE], "detail-type": [_MISMATCH_DETAIL_TYPE], "detail": {"nonce": [nonce]}},
    )
    _queue_target(ctx, bus_name, mismatch_rule, q_mismatch, "mq")

    match_rule = _create_rule(
        ctx, bus_name,
        {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE], "detail": {"nonce": [nonce]}},
    )
    _queue_target(ctx, bus_name, match_rule, q_ctrl, "cq")

    fn_arn = _create_worker(ctx)
    _lambda_target(ctx, bus_name, match_rule, fn_arn)

    sfn_role = _create_role(
        ctx, "states.amazonaws.com",
        {"Effect": "Allow", "Action": "events:PutEvents", "Resource": bus_arn},
    )
    definition = {
        "Comment": "sim2real xsvc-sfn-2 waitForTaskToken producer",
        "StartAt": "Publish",
        "States": {
            "Publish": {
                "Type": "Task",
                "Resource": "arn:aws:states:::events:putEvents.waitForTaskToken",
                "Parameters": {
                    "Entries": [{
                        "EventBusName": bus_arn,
                        "Source": _SOURCE,
                        "DetailType": _DETAIL_TYPE,
                        "Detail": {
                            "taskToken.$": "$$.Task.Token",
                            "job.$": "$.job",
                            "nonce": nonce,
                        },
                    }],
                },
                "TimeoutSeconds": 240,
                "End": True,
            },
        },
    }
    sm_arn = _create_state_machine(ctx, _xname(ctx, "sm")[:80], definition, sfn_role)

    # Launch, and relaunch with a fresh job id if an attempt does not finish — a rule or role is
    # not live the instant its create call returns. Each attempt's job id is unique, so the
    # output can be attributed to exactly one launch.
    attempts: list[dict] = []
    final = None
    t0 = time.monotonic()
    while time.monotonic() - t0 < _EXEC_BUDGET_S and final is None:
        job = f"job-{nonce}-{len(attempts)}"
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn, name=_xname(ctx, "ex")[:80], input=json.dumps({"job": job}),
        )["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: _tolerate(lambda: sfn.stop_execution(executionArn=a)))
        attempts.append({"job": job, "arn": exec_arn})
        attempt_deadline = time.monotonic() + _EXEC_ATTEMPT_S
        while time.monotonic() < attempt_deadline:
            d = sfn.describe_execution(executionArn=exec_arn)
            if d["status"] == "SUCCEEDED":
                final = (job, d)
                break
            if d["status"] != "RUNNING":
                print(f"[attempt] {exec_arn} ended {d['status']}: {d.get('error')} {d.get('cause')}")
                break
            time.sleep(2)
        else:
            _tolerate(lambda a=exec_arn: sfn.stop_execution(executionArn=a))
    assert final is not None, (
        f"no execution of the waitForTaskToken machine reached SUCCEEDED within {_EXEC_BUDGET_S:.0f}s "
        f"over {len(attempts)} attempt(s): "
        f"{[(a['job'], sfn.describe_execution(executionArn=a['arn'])['status']) for a in attempts]!r}"
    )
    job, described = final

    # The control queue sits on the SAME rule as the Lambda, so it received the very event the
    # worker saw: same id, same token.
    ctrl_sink: list[dict] = []
    _poll_until(
        lambda: _drain_once(ctx, q_ctrl["url"], ctrl_sink),
        lambda sink: any(b.get("detail", {}).get("job") == job for b in sink),
        timeout_s=60, interval_s=0.5,
        description=f"the matching rule's control queue receives the event for {job}",
    )
    event = next(b for b in ctrl_sink if b["detail"].get("job") == job)
    assert event["source"] == _SOURCE and event["detail-type"] == _DETAIL_TYPE, (
        f"the published envelope must be ({_SOURCE!r}, {_DETAIL_TYPE!r}); got "
        f"({event.get('source')!r}, {event.get('detail-type')!r})"
    )
    assert event["account"] == account and event["region"] == ctx.region, (
        f"the event must be attributed to {account!r}/{ctx.region!r}; got "
        f"{event.get('account')!r}/{event.get('region')!r}"
    )
    token = event["detail"].get("taskToken")
    assert isinstance(token, str) and len(token) > 50 and "$$" not in token, (
        f"detail.taskToken must be the substituted context-object token, not a literal path; got "
        f"{str(token)[:120]!r}"
    )
    assert event["detail"]["nonce"] == nonce, (
        f"the static Detail field must be carried verbatim; got {event['detail'].get('nonce')!r}"
    )

    expected = {
        "worker": "sim2real-xsvc-worker",
        "job": job,
        "eventId": event["id"],
        "detailType": _DETAIL_TYPE,
        "source": _SOURCE,
    }
    assert json.loads(described["output"]) == expected, (
        f"the execution's output must be the worker's SendTaskSuccess payload {expected!r}; got "
        f"{described.get('output')!r}"
    )

    # The token is spent: a second SendTaskSuccess with it must be refused.
    code = _error_code(lambda: sfn.send_task_success(taskToken=token, output="{}"))
    assert code == "TaskTimedOut", (
        f"re-using a completed task's token must fail with TaskTimedOut; got {code!r}"
    )

    # Negative control: the mismatched rule saw NOTHING from that publish, after the matching
    # rule delivered (the barrier) and after the control queue was drained further.
    mismatch_sink: list[dict] = []
    for _ in range(_DRAIN_EXTRA):
        _drain_once(ctx, q_ctrl["url"], ctrl_sink)
        _drain_once(ctx, q_mismatch["url"], mismatch_sink)
    assert mismatch_sink == [], (
        f"the rule on detail-type {_MISMATCH_DETAIL_TYPE!r} must receive nothing from a "
        f"{_DETAIL_TYPE!r} publish; it received {json.dumps(mismatch_sink)[:500]}"
    )

    # Repair: a publish that DOES carry the mismatched detail-type reaches that same queue (so its
    # silence was the pattern, not broken wiring), and never reaches the matching rule's queue.
    probe_job = f"probe-{nonce}"
    resp = events.put_events(Entries=[{
        "EventBusName": bus_name, "Source": _SOURCE, "DetailType": _MISMATCH_DETAIL_TYPE,
        "Detail": json.dumps({"nonce": nonce, "job": probe_job}),
    }])
    assert resp["FailedEntryCount"] == 0, f"probe PutEvents failed: {resp['Entries']!r}"
    _poll_until(
        lambda: _drain_once(ctx, q_mismatch["url"], mismatch_sink),
        lambda sink: any(b.get("detail", {}).get("job") == probe_job for b in sink),
        timeout_s=60, interval_s=0.5,
        description=f"the {_MISMATCH_DETAIL_TYPE!r} rule's queue receives the direct probe",
    )
    for _ in range(_DRAIN_EXTRA):
        _drain_once(ctx, q_ctrl["url"], ctrl_sink)
    leaked = [b for b in ctrl_sink if b.get("detail", {}).get("job") == probe_job]
    assert leaked == [], (
        f"the {_DETAIL_TYPE!r} rule must not match a {_MISMATCH_DETAIL_TYPE!r} event; its control "
        f"queue received {json.dumps(leaked)[:400]}"
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"
_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _error_code(fn) -> str:
    """The error code of a call expected to fail; RAISES if the call succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError(f"the call was expected to be refused but succeeded: {resp!r}")


def _tolerate(fn, *tolerated: str, leak: str = "") -> None:
    """Run a teardown call. With a leak label (only the registered cleanups pass one), an error code
    outside `tolerated` raises as a leak; without one, a refused teardown call is ignored."""
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


def _create_bus(ctx) -> tuple[str, str]:
    events = ctx.client("events")
    name = _xname(ctx, "bus")[:64]
    arn = events.create_event_bus(
        Name=name, Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["EventBusArn"]

    def _delete(n=name):
        _tolerate(lambda: events.delete_event_bus(Name=n), "ResourceNotFoundException", leak=f"could not delete event bus {n}")

    ctx.on_cleanup(_delete)
    return name, arn


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


def _create_rule(ctx, bus_name: str, pattern: dict) -> dict[str, str]:
    events = ctx.client("events")
    name = _xname(ctx, "rule")[:64]
    arn = events.put_rule(
        Name=name, EventBusName=bus_name, EventPattern=json.dumps(pattern),
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["RuleArn"]

    def _teardown(n=name):
        ids = [t["Id"] for t in events.list_targets_by_rule(Rule=n, EventBusName=bus_name)["Targets"]]
        if ids:
            _tolerate(lambda: events.remove_targets(Rule=n, EventBusName=bus_name, Ids=ids, Force=True))
        _tolerate(lambda: events.delete_rule(Name=n, EventBusName=bus_name, Force=True), "ResourceNotFoundException", leak=f"could not delete rule {n}")

    ctx.on_cleanup(_teardown)
    return {"name": name, "arn": arn}


def _queue_target(ctx, bus_name: str, rule: dict, queue: dict, target_id: str) -> None:
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
        Rule=rule["name"], EventBusName=bus_name, Targets=[{"Id": target_id, "Arn": queue["arn"]}],
    )
    assert resp["FailedEntryCount"] == 0, f"PutTargets(queue) failed: {resp['FailedEntries']!r}"


def _zip_source(src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", src)
    return buf.getvalue()


def _create_worker(ctx) -> str:
    """The Lambda worker. Its role grants states:SendTaskSuccess and NO logs permissions, so the
    function cannot create /aws/lambda/<fn>; the log-group reap below is a belt for that."""
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    name = _xname(ctx, "fn")[:64]
    group = f"/aws/lambda/{name}"

    def _reap_logs(g=group):
        for _ in range(5):
            _tolerate(lambda: logs.delete_log_group(logGroupName=g))
            time.sleep(2)
            if not logs.describe_log_groups(logGroupNamePrefix=g)["logGroups"]:
                return
        raise RuntimeError(f"log group {g} kept reappearing")

    ctx.on_cleanup(_reap_logs)  # registered BEFORE the create so LIFO runs it after the delete
    role_arn = _create_role(
        ctx, "lambda.amazonaws.com",
        {"Effect": "Allow", "Action": "states:SendTaskSuccess", "Resource": "*"},
    )
    deadline = time.monotonic() + 90
    while True:
        try:
            arn = lam.create_function(
                FunctionName=name, Runtime="python3.12", Handler="index.handler", Role=role_arn,
                Code={"ZipFile": _zip_source(_WORKER_SRC)}, Timeout=90, MemorySize=128,
                Tags=dict(_TAGS),
            )["FunctionArn"]
            break
        except ClientError as exc:
            if (exc.response["Error"]["Code"] != "InvalidParameterValueException"
                    or time.monotonic() > deadline):
                raise
            time.sleep(3)

    def _delete(n=name):
        _tolerate(lambda: lam.delete_function(FunctionName=n), "ResourceNotFoundException", leak=f"could not delete function {n}")

    ctx.on_cleanup(_delete)
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name)["State"],
        lambda s: s == "Active", timeout_s=90, interval_s=2,
        description=f"Lambda {name} becomes Active",
    )
    return arn


def _lambda_target(ctx, bus_name: str, rule: dict, fn_arn: str) -> None:
    ctx.client("lambda").add_permission(
        FunctionName=fn_arn, StatementId="events-invoke", Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com", SourceArn=rule["arn"],
    )
    resp = ctx.client("events").put_targets(
        Rule=rule["name"], EventBusName=bus_name, Targets=[{"Id": "fn", "Arn": fn_arn}],
    )
    assert resp["FailedEntryCount"] == 0, f"PutTargets(lambda) failed: {resp['FailedEntries']!r}"


def _drain_once(ctx, url: str, sink: list) -> list:
    """One long-poll receive; every delivered event body is appended to sink."""
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
    for msg in resp.get("Messages", []):
        sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
        sink.append(json.loads(msg["Body"]))
    return sink


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
