"""xsvc-lambda-1-durable-stop-emits-stopped-status-change-to-sqs."""
from __future__ import annotations

import datetime as _dt
import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "xsvc-lambda-1-durable-stop-emits-stopped-status-change-to-sqs"
GROUP = "event-propagation"
SERVICES = ["events", "lambda", "sqs"]

_HANDLER = '''
from aws_durable_execution_sdk_python import DurableContext, durable_execution
from aws_durable_execution_sdk_python.config import Duration


@durable_execution
def lambda_handler(event, context: DurableContext):
    context.wait(Duration.from_seconds(int(event.get("wait_seconds", 5))))
    if event.get("fail"):
        raise RuntimeError("sim2real deliberate failure")
    return {"ok": True}
'''


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e",
      "concern:eventing", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """StopDurableExecution on a RUNNING execution emits a STOPPED status-change event, delivered
    by a default-bus rule to SQS, whose endTimestamp equals the StopTimestamp the call returned.
    """
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")

    role_arn = _create_durable_role(ctx)
    fn_name = ctx.unique_name("sim2real-xsvc-durstop-")
    fn_arn = _predicted_fn_arn(ctx, fn_name)
    queue_url, _rule = _status_queue(ctx, fn_arn)
    created = _create_durable_function(ctx, fn_name, role_arn, _HANDLER, execution_timeout=600)
    assert created == fn_arn, f"CreateFunction returned {created!r}, expected {fn_arn!r}"
    _await_rule_live(ctx, sqs, queue_url, fn_name, {"wait_seconds": 1}, "SUCCEEDED")

    exec_name = ctx.unique_name("stop-")
    exec_arn = _start(lam, fn_name, exec_name, {"wait_seconds": 300})

    def _mine(evs: list[dict]) -> list[dict]:
        return [e for e in evs if e["detail"].get("durableExecutionArn") == exec_arn]

    # Stop only after RUNNING is delivered, so the pipeline has already seen this execution start.
    first = _drain(sqs, queue_url,
                   until=lambda evs: any(e["detail"]["status"] == "RUNNING" for e in _mine(evs)),
                   timeout_s=120.0)
    assert [e["detail"]["status"] for e in _mine(first)] == ["RUNNING"], (
        f"before the stop only RUNNING may be delivered, got {[e['detail'] for e in first]!r}"
    )

    stop = lam.stop_durable_execution(
        DurableExecutionArn=exec_arn,
        Error={"ErrorType": "Sim2RealStop", "ErrorMessage": "stopped by " + CHECK},
    )
    stop_ts = stop["StopTimestamp"]

    later = _drain(sqs, queue_url,
                   until=lambda evs: any(e["detail"]["status"] == "STOPPED" for e in _mine(evs)),
                   timeout_s=180.0)
    statuses = sorted({e["detail"]["status"] for e in _mine(later)})
    assert statuses == ["STOPPED"], f"after the stop expected only STOPPED, got {statuses!r}"
    d = next(e for e in _mine(later) if e["detail"]["status"] == "STOPPED")["detail"]
    assert d["durableExecutionName"] == exec_name, f"durableExecutionName {d.get('durableExecutionName')!r}"
    assert d["functionArn"] == fn_arn + ":$LATEST", f"functionArn {d.get('functionArn')!r}"
    running = _mine(first)[0]["detail"]
    assert d["startTimestamp"] == running["startTimestamp"], (
        f"STOPPED startTimestamp {d['startTimestamp']!r} != RUNNING {running['startTimestamp']!r}"
    )
    assert "endTimestamp" in d, f"STOPPED event lacks endTimestamp: {d!r}"
    assert _ms(_ts(d["endTimestamp"])) == _ms(stop_ts), (
        f"STOPPED endTimestamp {d['endTimestamp']!r} != StopTimestamp {stop_ts!r}"
    )

    got = lam.get_durable_execution(DurableExecutionArn=exec_arn)
    assert got["Status"] == "STOPPED", f"GetDurableExecution status {got['Status']!r}"
    assert got.get("Error", {}).get("ErrorType") == "Sim2RealStop", (
        f"stop Error not recorded on the execution: {got.get('Error')!r}"
    )


def _ts(value: str) -> _dt.datetime:
    return _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def _ms(value: _dt.datetime) -> int:
    return round(value.timestamp() * 1000)


def _zip(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", source)
    return buf.getvalue()


def _create_durable_role(ctx: Any) -> str:
    # Inline policy, deliberately WITHOUT logs:CreateLogGroup: the check owns the log group
    # (see _own_log_group), so a log flush buffered past delete_function cannot recreate it.
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-durrole-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": "arn:aws:logs:*:*:log-group:/aws/lambda/sim2real-xsvc-*:*"}, {
        "Effect": "Allow", "Action": ["lambda:CheckpointDurableExecution", "lambda:GetDurableExecutionState"], "Resource": "*"}]}
    iam.put_role_policy(RoleName=name, PolicyName="exec", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="exec"))
    return arn


def _own_log_group(ctx: Any, fn_name: str) -> None:
    # The check creates the function's log group itself, BEFORE the function, and the role
    # cannot create one. LIFO cleanup deletes it after delete_function and before the role,
    # so a late buffered flush gets AccessDenied instead of resurrecting the group.
    logs = ctx.client("logs")
    group = f"/aws/lambda/{fn_name}"
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK})

    def _reap() -> None:
        for _ in range(6):
            try:
                logs.delete_log_group(logGroupName=group)
            except logs.exceptions.ResourceNotFoundException:
                pass
            time.sleep(5)
            found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
            if not any(g["logGroupName"] == group for g in found):
                return
        raise RuntimeError(f"log group {group} kept reappearing")

    ctx.on_cleanup(_reap)


def _predicted_fn_arn(ctx: Any, name: str) -> str:
    account = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:lambda:{ctx.region}:{account}:function:{name}"


def _create_durable_function(ctx: Any, name: str, role_arn: str, source: str,
                             execution_timeout: int) -> str:
    lam = ctx.client("lambda")
    _own_log_group(ctx, name)
    deadline = time.monotonic() + 120
    while True:
        try:
            arn = lam.create_function(
                FunctionName=name, Runtime="python3.13", Role=role_arn,
                Handler="lambda_function.lambda_handler", Code={"ZipFile": _zip(source)},
                Timeout=60, MemorySize=256,
                DurableConfig={"ExecutionTimeout": execution_timeout, "RetentionPeriodInDays": 1},
                Tags={"sim2real": CHECK},
            )["FunctionArn"]
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            # IAM propagation: the new role is not yet assumable by Lambda.
            if "cannot be assumed" not in str(exc) or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return arn


def _status_queue(ctx: Any, fn_arn: str, statuses: list[str] | None = None) -> tuple[str, str]:
    """Queue + default-bus rule for this function's durable status events (optionally
    narrowed to `statuses`). The functionArn prefix keeps a sibling run's events out."""
    sqs = ctx.client("sqs")
    ev = ctx.client("events")
    qname = ctx.unique_name("sim2real-xsvc-durq-")
    url = sqs.create_queue(QueueName=qname, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    qarn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    detail: dict = {"functionArn": [{"prefix": fn_arn}]}
    if statuses:
        detail["status"] = statuses
    pattern = {"source": ["aws.lambda"], "detail-type": ["Durable Execution Status Change"],
               "detail": detail}
    rule = ctx.unique_name("sim2real-xsvc-durrule-")
    rule_arn = ev.put_rule(Name=rule, EventPattern=json.dumps(pattern), State="ENABLED")["RuleArn"]
    ctx.on_cleanup(lambda: ev.delete_rule(Name=rule))
    policy = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"},
        "Action": "sqs:SendMessage", "Resource": qarn,
        "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}}}]}
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    ev.put_targets(Rule=rule, Targets=[{"Id": "q", "Arn": qarn}])
    ctx.on_cleanup(lambda: ev.remove_targets(Rule=rule, Ids=["q"]))
    return url, rule


def _start(lam: Any, fn_name: str, exec_name: str, payload: dict) -> str:
    resp = lam.invoke(FunctionName=fn_name, Qualifier="$LATEST", InvocationType="Event",
                      Payload=json.dumps(payload).encode(), DurableExecutionName=exec_name)
    assert resp["StatusCode"] == 202, f"async durable Invoke returned {resp['StatusCode']!r}"
    arn = resp.get("DurableExecutionArn")
    assert arn, f"async durable Invoke returned no DurableExecutionArn: {sorted(resp)!r}"
    return arn


def _await_rule_live(ctx: Any, sqs: Any, url: str, fn_name: str, payload: dict, status: str) -> list[dict]:
    """A new rule is eventually consistent, and a status event emitted before it is live is
    simply not routed. Run a warm-up execution and wait for its terminal event at the queue:
    that arrival is the observable proof the rule is live before the real execution starts."""
    lam = ctx.client("lambda")
    arn = _start(lam, fn_name, ctx.unique_name("warm-"), payload)
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        met, events = _collect(sqs, url, until=lambda evs: any(
            e["detail"].get("durableExecutionArn") == arn and e["detail"].get("status") == status
            for e in evs), timeout_s=30.0)
        if met:
            return events
        arn = _start(lam, fn_name, ctx.unique_name("warm-"), payload)
    raise AssertionError(f"rule never delivered a warm-up {status} event for {fn_name!r} within 240s")


def _collect(sqs: Any, url: str, until, timeout_s: float) -> tuple[bool, list[dict]]:
    """Receive (and delete) events until `until(events)` holds or timeout_s passes; return
    (whether it held, the events), de-duplicated by event id because EventBridge delivery is
    at-least-once."""
    seen: dict[str, dict] = {}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=10).get("Messages", [])
        for m in msgs:
            body = json.loads(m["Body"])
            seen.setdefault(body["id"], body)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
        if until(list(seen.values())):
            return True, list(seen.values())
    return False, list(seen.values())


def _drain(sqs: Any, url: str, until, timeout_s: float) -> list[dict]:
    """``_collect`` that raises when `until(events)` does not hold within timeout_s."""
    met, events = _collect(sqs, url, until, timeout_s)
    if not met:
        raise AssertionError(
            f"condition not met within {timeout_s}s; delivered: {[e.get('detail') for e in events]!r}"
        )
    return events


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
