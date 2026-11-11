"""obs-sfn-3-express-fail-events-to-unpermitted-lambda-subscriber-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-sfn-3-express-fail-events-to-unpermitted-lambda-subscriber-rejected"
GROUP = "observability"
SERVICES = ["cloudwatch", "lambda", "logs", "stepfunctions"]

_READY_BUDGET_S = 360.0
_DELIVERY_BUDGET_S = 420.0
_TRAIL_S = 30.0
_MARK = "SIM2REAL_SUB"


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:negative-classes",
    "concern:eventing",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """PutSubscriptionFilter to a function that does not grant logs.amazonaws.com fails with the
    exact InvalidParameterException, leaves no filter and the failure logged meanwhile never reaches
    it; after the grant the same filter delivers only the next FailStateEntered event."""
    sfn = ctx.client("stepfunctions")
    logs = ctx.client("logs")
    lam = ctx.client("lambda")
    account = ctx.client("sts").get_caller_identity()["Account"]

    group = ctx.unique_name("/aws/vendedlogs/states/sim2real-xsvc-obssfn3-")
    logs.create_log_group(logGroupName=group, tags={"sim2real": "cloudwatch__lambda__logs__sfn"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    group_arn = f"arn:aws:logs:{ctx.region}:{account}:log-group:{group}"

    fn_name, fn_arn, fn_group = _subscriber_lambda(ctx)

    def put_filter():
        return logs.put_subscription_filter(
            logGroupName=group,
            filterName="fail-state-entered",
            filterPattern='{$.type = "FailStateEntered"}',
            destinationArn=fn_arn,
        )

    # ---- the refusal: no invoke permission for logs.amazonaws.com ------------------------------ #
    err = _error(
        put_filter,
        # wrongly accepted: register the teardown before failing
        on_success=lambda: ctx.on_cleanup(
            lambda: logs.delete_subscription_filter(logGroupName=group, filterName="fail-state-entered")
        ),
    )
    expected = (
        "InvalidParameterException",
        "Could not execute the lambda function. Make sure you have given CloudWatch Logs "
        "permission to execute your function.",
    )
    assert err == expected, (
        f"PutSubscriptionFilter to {fn_name}, which grants logs.amazonaws.com no invoke permission, "
        f"returned {err!r}; real AWS refuses it with {expected!r}"
    )
    left = logs.describe_subscription_filters(logGroupName=group)["subscriptionFilters"]
    assert left == [], f"the refused PutSubscriptionFilter left filters behind: {left!r}"

    machine = _express_machine(ctx, sfn, _states_role(ctx), f"{group_arn}:*")
    _await_delivery_ready(ctx, sfn, logs, machine, group)

    # ---- effect absent: a failure logged while unwired never reaches the function -------------- #
    first = sfn.start_sync_execution(stateMachineArn=machine, input=json.dumps({"ok": False}))
    assert first["status"] == "FAILED", f"the first failing execution ended {first['status']!r}"
    _poll_until(
        lambda: _log_events(logs, group),
        lambda evs: any(
            e.get("type") == "FailStateEntered" and e.get("execution_arn") == first["executionArn"]
            for e in evs
        ),
        timeout_s=_DELIVERY_BUDGET_S,
        interval_s=10.0,
        description="the unwired failure's FailStateEntered reaching the log group (the barrier)",
    )
    # The positive control below is ordered after this failure, so its delivery bounds the
    # absence: the subscriber must then hold the second failure and never this one.
    got = _subscriber_records(logs, fn_group)
    assert got == [], (
        f"the subscriber {fn_name} received {got!r} although no subscription filter was ever "
        f"accepted for {group}"
    )

    # ---- positive control: repair the one broken thing, the next failure is delivered --------- #
    lam.add_permission(
        FunctionName=fn_name,
        StatementId="cwlogs-invoke",
        Action="lambda:InvokeFunction",
        Principal="logs.amazonaws.com",
        SourceArn=f"{group_arn}:*",
        SourceAccount=account,
    )
    _retry(
        put_filter,
        code="InvalidParameterException",
        budget_s=90.0,
        description="PutSubscriptionFilter while the fresh logs.amazonaws.com invoke grant propagates",
    )
    ctx.on_cleanup(
        lambda: logs.delete_subscription_filter(logGroupName=group, filterName="fail-state-entered")
    )
    second = sfn.start_sync_execution(stateMachineArn=machine, input=json.dumps({"ok": False}))
    assert second["status"] == "FAILED", f"the second failing execution ended {second['status']!r}"
    received = _poll_until(
        lambda: _subscriber_records(logs, fn_group),
        lambda records: any(r["execution_arn"] == second["executionArn"] for r in records),
        timeout_s=_DELIVERY_BUDGET_S,
        interval_s=5.0,
        description=f"the repaired subscriber {fn_name} receiving the second failure",
    )
    # Re-read until one read adds nothing, so records that trail the control are graded too.
    trail_deadline = time.monotonic() + _TRAIL_S
    while time.monotonic() < trail_deadline:
        time.sleep(5.0)
        again = _subscriber_records(logs, fn_group)
        if again == received:
            break
        received = again
    arns = sorted({r["execution_arn"] for r in received})
    assert arns == [second["executionArn"]], (
        f"after the repair the subscriber received execution_arns {arns!r}; expected exactly the "
        f"failure started after the filter existed, {second['executionArn']!r}, and never the "
        f"earlier unwired one {first['executionArn']!r}"
    )
    assert {r["type"] for r in received} == {"FailStateEntered"}, (
        f"the repaired subscriber received types {sorted({r['type'] for r in received})!r}"
    )


def _error(fn, *, on_success):
    """(code, message) of the ClientError fn raises. A call that SUCCEEDS runs on_success and then
    fails loudly."""
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    on_success()
    raise AssertionError(f"the call was expected to be refused but SUCCEEDED: {resp!r}")


_TAG = "cloudwatch__lambda__logs__sfn"
_DEFINITION = json.dumps(
    {
        "StartAt": "Route",
        "States": {
            "Route": {
                "Type": "Choice",
                "Choices": [{"Variable": "$.ok", "BooleanEquals": True, "Next": "Fine"}],
                "Default": "Boom",
            },
            "Fine": {"Type": "Pass", "End": True},
            "Boom": {
                "Type": "Fail",
                "Error": "Sim2RealDeliberateFailure",
                "Cause": "obs-sfn-3 express failure",
            },
        },
    }
)
_LOG_ACTIONS = [
    "logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery",
    "logs:DeleteLogDelivery", "logs:ListLogDeliveries", "logs:PutResourcePolicy",
    "logs:DescribeResourcePolicies", "logs:DescribeLogGroups",
    "logs:CreateLogStream", "logs:PutLogEvents",
]
_SUBSCRIBER_CODE = f'''
import base64, gzip, json

def handler(event, context):
    data = json.loads(gzip.decompress(base64.b64decode(event["awslogs"]["data"])))
    if data.get("messageType") != "DATA_MESSAGE":
        return
    for le in data["logEvents"]:
        msg = json.loads(le["message"])
        print("{_MARK} " + json.dumps({{
            "id": le["id"], "type": msg.get("type"), "execution_arn": msg.get("execution_arn"),
            "group": data["logGroup"], "filters": data["subscriptionFilters"]}}))
'''


def _role(ctx, service: str, label: str, actions: list[str], resource: str) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name(f"sim2real-xsvc-obssfn3-{label}-")[:64]
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": service},
                     "Action": "sts:AssumeRole"}
                ],
            }
        ),
        Description=f"sim2real {_TAG} {label}",
        Tags=[{"Key": "sim2real", "Value": _TAG}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="inline",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": actions, "Resource": resource}],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    return name, arn


def _states_role(ctx) -> str:
    return _role(ctx, "states.amazonaws.com", "sfn", _LOG_ACTIONS, "*")[1]


def _subscriber_lambda(ctx) -> tuple[str, str, str]:
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    fn_name = ctx.unique_name("sim2real-xsvc-obssfn3-sub-")
    fn_group = f"/aws/lambda/{fn_name}"
    # Registered BEFORE the function exists so LIFO reaps it AFTER delete_function: a buffered
    # invocation log can flush after the delete and recreate the group.
    ctx.on_cleanup(lambda: _reap_log_group(logs, fn_group))
    logs.create_log_group(logGroupName=fn_group, tags={"sim2real": _TAG})
    _, role_arn = _role(
        ctx, "lambda.amazonaws.com", "fn", ["logs:CreateLogStream", "logs:PutLogEvents"],
        f"arn:aws:logs:{ctx.region}:{account}:log-group:{fn_group}:*",
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", _SUBSCRIBER_CODE)
    fn_arn = _retry(
        lambda: lam.create_function(
            FunctionName=fn_name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": buf.getvalue()},
            Timeout=30,
            Tags={"sim2real": _TAG},
        )["FunctionArn"],
        code="InvalidParameterValueException",
        budget_s=90.0,
        description="CreateFunction while the fresh Lambda role becomes assumable",
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    lam.get_waiter("function_active_v2").wait(
        FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    return fn_name, fn_arn, fn_group


def _reap_log_group(logs, name: str) -> None:
    """Delete, then watch for a late flush recreating the group; bounded, and loud if it never
    converges rather than hanging."""
    for _ in range(4):
        try:
            logs.delete_log_group(logGroupName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(10.0)
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if not any(g["logGroupName"] == name for g in groups):
            return
    raise RuntimeError(f"log group {name} kept reappearing after delete")


def _express_machine(ctx, sfn, role_arn: str, log_group_arn: str) -> str:
    name = ctx.unique_name("sim2real-xsvc-obssfn3-x-")[:80]
    arn = _retry(
        lambda: sfn.create_state_machine(
            name=name,
            definition=_DEFINITION,
            roleArn=role_arn,
            type="EXPRESS",
            loggingConfiguration={
                "level": "ALL",
                "includeExecutionData": True,
                "destinations": [{"cloudWatchLogsLogGroup": {"logGroupArn": log_group_arn}}],
            },
            tags=[{"key": "sim2real", "value": _TAG}],
        )["stateMachineArn"],
        code="AccessDeniedException",
        budget_s=120.0,
        description="CreateStateMachine while the fresh states role becomes assumable",
    )
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _await_delivery_ready(ctx, sfn, logs, machine: str, group: str) -> list[str]:
    """Start SUCCESSFUL executions until one of them is delivered to the group; return all of
    their ARNs (none may ever reach a failure surface)."""
    deadline = time.monotonic() + _READY_BUDGET_S
    started: list[str] = []
    next_start = 0.0
    while time.monotonic() < deadline:
        # One warm-up execution per 15 s; the group is read every 2 s in between.
        if time.monotonic() >= next_start:
            resp = sfn.start_sync_execution(stateMachineArn=machine, input=json.dumps({"ok": True}))
            assert resp["status"] == "SUCCEEDED", f"warm-up execution ended {resp['status']!r}"
            started.append(resp["executionArn"])
            next_start = time.monotonic() + 15.0
        time.sleep(2.0)
        delivered = {e.get("execution_arn") for e in _log_events(logs, group)}
        if delivered & set(started):
            return started
    raise AssertionError(
        f"the EXPRESS machine's level-ALL log delivery never delivered any of {len(started)} "
        f"successful warm-up executions to {group} within {_READY_BUDGET_S}s"
    )


def _log_events(logs, group: str) -> list[dict]:
    out: list[dict] = []
    for page in logs.get_paginator("filter_log_events").paginate(logGroupName=group):
        out.extend(json.loads(e["message"]) for e in page["events"])
    return out


def _subscriber_records(logs, fn_group: str) -> list[dict]:
    out: list[dict] = []
    try:
        for page in logs.get_paginator("filter_log_events").paginate(
            logGroupName=fn_group, filterPattern=f'"{_MARK}"'
        ):
            for e in page["events"]:
                line = e["message"].strip()
                out.append(json.loads(line[line.index(_MARK) + len(_MARK):]))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    return sorted(out, key=lambda r: r["id"])


def _retry(call, *, code: str, budget_s: float, description: str):
    """Retry ONLY the one propagation refusal named, bounded by a deadline that raises."""
    deadline = time.monotonic() + budget_s
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return call()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != code:
                raise
            last = exc
            time.sleep(5.0)
    raise AssertionError(f"{description}: still refused after {budget_s}s; last {last!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} did not happen within {timeout_s}s; last read {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
