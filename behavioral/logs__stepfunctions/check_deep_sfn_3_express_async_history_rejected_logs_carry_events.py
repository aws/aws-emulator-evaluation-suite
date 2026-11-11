"""deep-sfn-3-express-async-history-rejected-logs-carry-events."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-3-express-async-history-rejected-logs-carry-events"
GROUP = "express-observability"
SERVICES = ["logs", "stepfunctions"]

_EXPECTED_HISTORY_ERROR = "InvalidArn"
_DEFINITION = {
    "StartAt": "Shape",
    "States": {"Shape": {"Type": "Pass", "Parameters": {"echo.$": "$.nonce", "kind": "express"},
                         "End": True}},
}


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetExecutionHistory on an async EXPRESS execution is refused with InvalidArn and its exact message;
    the loggingConfiguration log group carries one ExecutionStarted and one ExecutionSucceeded for that
    execution ARN, with the real input and output, in order.
    """
    sfn = ctx.client("stepfunctions")
    logs = ctx.client("logs")

    group = f"/aws/vendedlogs/states/{ctx.unique_name('sim2real-xsvc-sfn-interp-')}"
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    group_arn = _log_group_arn(logs, group)

    role_arn = _sfn_role(ctx)
    sm_arn = _create_state_machine(
        ctx, role_arn, _DEFINITION, type="EXPRESS",
        loggingConfiguration={"level": "ALL", "includeExecutionData": True,
                              "destinations": [{"cloudWatchLogsLogGroup": {"logGroupArn": group_arn}}]},
    )

    # --- warm-up barrier -------------------------------------------------------------------
    # An execution started in the first seconds after CreateStateMachine is never delivered to the
    # log group, while one started ~10 s later is: vended delivery activates shortly after the
    # logging configuration is written. So warm-up executions are
    # started until ONE of them is visible in the group; only then is the asserted execution run.
    def _records_for(arn):
        found = {}
        kwargs = {"logGroupName": group, "startTime": 0}
        while True:
            page = logs.filter_log_events(**kwargs)
            for ev in page.get("events", []):
                try:
                    rec = json.loads(ev["message"])
                except ValueError:
                    continue
                if rec.get("execution_arn") == arn:
                    found.setdefault(rec.get("type"), []).append(rec)
            if not page.get("nextToken"):
                return found
            kwargs["nextToken"] = page["nextToken"]

    warm = []

    def _warm_seen():
        warm.append(sfn.start_execution(stateMachineArn=sm_arn,
                                        input=json.dumps({"nonce": "warmup"}))["executionArn"])
        return any("ExecutionSucceeded" in _records_for(a) for a in warm)

    _poll_until(_warm_seen, bool, timeout_s=180, interval_s=8,
                description=f"any warm-up EXPRESS execution delivered to {group}")

    nonce = uuid.uuid4().hex
    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps({"nonce": nonce}))["executionArn"]
    sm_name = sm_arn.rsplit(":", 1)[1]
    assert f":express:{sm_name}:" in exec_arn, (
        f"an EXPRESS StartExecution must mint an ':express:' execution ARN for {sm_name!r}; got "
        f"{exec_arn!r}"
    )

    # --- the negative: no queryable history for an EXPRESS execution -------------------------
    try:
        resp = sfn.get_execution_history(executionArn=exec_arn)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
    else:
        raise AssertionError(
            f"GetExecutionHistory must REJECT an EXPRESS execution ARN; it returned "
            f"{[e.get('type') for e in resp.get('events', [])]!r}"
        )
    assert code == _EXPECTED_HISTORY_ERROR, (
        f"GetExecutionHistory on an EXPRESS execution must fail with exactly "
        f"{_EXPECTED_HISTORY_ERROR!r}; got {code!r}"
    )
    expected = "Invalid Arn: 'Resource type not valid in this context: express'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # --- positive control: the log group carries the lifecycle -------------------------------
    found = _poll_until(lambda: _records_for(exec_arn), lambda f: "ExecutionStarted" in f and "ExecutionSucceeded" in f,
                        timeout_s=180, interval_s=5,
                        description=f"ExecutionStarted+ExecutionSucceeded for {exec_arn} in {group}")
    assert len(found["ExecutionStarted"]) == 1 and len(found["ExecutionSucceeded"]) == 1, (
        f"the log group must carry exactly one ExecutionStarted and one ExecutionSucceeded for the "
        f"execution; got counts {({k: len(v) for k, v in found.items()})!r}"
    )
    started, succeeded = found["ExecutionStarted"][0], found["ExecutionSucceeded"][0]
    s_in = json.loads(started["details"]["input"])
    assert s_in == {"nonce": nonce}, f"ExecutionStarted must carry the real input; got {started!r}"
    s_out = json.loads(succeeded["details"]["output"])
    assert s_out == {"echo": nonce, "kind": "express"}, (
        f"ExecutionSucceeded must carry the Pass state's output; got {succeeded!r}"
    )
    assert int(started["event_timestamp"]) <= int(succeeded["event_timestamp"]), (
        f"ExecutionStarted ({started['event_timestamp']}) cannot follow ExecutionSucceeded "
        f"({succeeded['event_timestamp']})"
    )


def _log_group_arn(logs, group):
    groups = []
    kwargs = {"logGroupNamePrefix": group}
    while True:
        page = logs.describe_log_groups(**kwargs)
        groups.extend(g for g in page["logGroups"] if g["logGroupName"] == group)
        if not page.get("nextToken"):
            break
        kwargs["nextToken"] = page["nextToken"]
    assert len(groups) == 1, f"log group {group!r} must exist exactly once; found {groups!r}"
    arn = groups[0]["arn"]
    return arn if arn.endswith(":*") else arn + ":*"


_TRUST = json.dumps({"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}]})


def _poll_until(probe, predicate, *, timeout_s, interval_s=1.0, description="condition"):
    """A bounded retry that RAISES on its deadline; never returns a stale value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")


def _sfn_role(ctx) -> str:
    """A role Step Functions can assume, carrying the CloudWatch Logs vended-delivery actions the
    service documents as required for a loggingConfiguration."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-sfn-interp-role-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Description=f"sim2real {CHECK}",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _delete():
        try:
            iam.delete_role_policy(RoleName=name, PolicyName="inline")
        except iam.exceptions.NoSuchEntityException:
            pass
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_delete)
    iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Resource": "*", "Action": [
            "logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery",
            "logs:DeleteLogDelivery", "logs:ListLogDeliveries", "logs:PutResourcePolicy",
            "logs:DescribeResourcePolicies", "logs:DescribeLogGroups"]}],
    }))
    return arn


def _create_state_machine(ctx, role_arn, definition, **extra) -> str:
    """CreateStateMachine, bounded-retrying only the AccessDeniedException raised while the fresh
    role's trust propagates."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-sfn-interp-sm-")
    deadline = time.monotonic() + 120.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn,
                tags=[{"key": "sim2real", "value": CHECK}], **extra,
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(5.0)


def _start(ctx, sm_arn, payload) -> str:
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps(payload))["executionArn"]

    def _stop():
        if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
            sfn.stop_execution(executionArn=exec_arn)

    ctx.on_cleanup(_stop)
    return exec_arn


def _wait_terminal(ctx, exec_arn, timeout_s=150.0) -> dict:
    sfn = ctx.client("stepfunctions")
    return _poll_until(lambda: sfn.describe_execution(executionArn=exec_arn),
                       lambda d: d["status"] != "RUNNING", timeout_s=timeout_s,
                       description=f"execution {exec_arn} leaving RUNNING")


def _history(ctx, exec_arn) -> list:
    sfn = ctx.client("stepfunctions")
    events, kwargs = [], {"executionArn": exec_arn}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        events.extend(resp["events"])
        if not resp.get("nextToken"):
            return sorted(events, key=lambda e: e["id"])
        kwargs["nextToken"] = resp["nextToken"]


def _entered(events, state) -> list:
    return [e for e in events if e.get("stateEnteredEventDetails", {}).get("name") == state]


def _exited(events, state) -> list:
    return [e for e in events if e.get("stateExitedEventDetails", {}).get("name") == state]


def _state_span(events, state):
    """(entered, exited) timestamps of a state visited exactly once."""
    en, ex = _entered(events, state), _exited(events, state)
    assert len(en) == 1 and len(ex) == 1, (
        f"state {state!r} must be entered and exited exactly once; got {len(en)} entered / "
        f"{len(ex)} exited in {[e['type'] for e in events]!r}"
    )
    return en[0]["timestamp"], ex[0]["timestamp"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
