"""deep-sfn-2-sfn-jsonata-context-redrive-count-joins-describe-execution."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-2-sfn-jsonata-context-redrive-count-joins-describe-execution"
GROUP = 'context-object'
SERVICES = ['stepfunctions']


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
    "cap:c3",
)
def run(ctx) -> None:
    """$$.Execution.RedriveCount reads 0 then 1 across RedriveExecution (JSONPath and JSONata),
    the not-re-run state keeps 0, and it equals DescribeExecution's redriveCount and the
    ExecutionRedriven event."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_role(ctx)
    activity_arn = _create_activity(ctx)

    definition = {
        "StartAt": "Stamp",
        "States": {
            "Stamp": {
                "Type": "Pass",
                "Parameters": {"rc.$": "$$.Execution.RedriveCount"},
                "ResultPath": "$.before",
                "Next": "Work",
            },
            "Work": {
                "Type": "Task",
                "Resource": activity_arn,
                "Parameters": {"rc.$": "$$.Execution.RedriveCount", "before.$": "$.before.rc"},
                "ResultPath": "$.work",
                "TimeoutSeconds": 120,
                "Next": "After",
            },
            "After": {
                "Type": "Pass",
                "Parameters": {"rc.$": "$$.Execution.RedriveCount"},
                "ResultPath": "$.after",
                "Next": "AfterNata",
            },
            "AfterNata": {
                "Type": "Pass",
                "QueryLanguage": "JSONata",
                "Output": "{% $merge([$states.input, {'nata': $states.context.Execution.RedriveCount}]) %}",
                "End": True,
            },
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn)
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
        input=json.dumps({"orig": True}),
    )["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, exec_arn))

    # The activity worker is the side channel: it reads the RedriveCount the interpreter passed in.
    token, task_input = _poll_activity_task(ctx, activity_arn)
    assert task_input == {"rc": 0, "before": 0}, (
        f"the original run's activity input was {task_input!r}; RedriveCount must read 0"
    )
    sfn.send_task_failure(taskToken=token, error="SimRedriveProbe", cause="induced failure")
    failed = _wait_status(ctx, exec_arn, lambda s: s != "RUNNING")
    assert (failed["status"], failed["redriveStatus"], failed.get("redriveCount", 0)) == (
        "FAILED", "REDRIVABLE", 0), (
        f"after the induced failure: status {failed['status']!r}, redriveStatus "
        f"{failed.get('redriveStatus')!r}, redriveCount {failed.get('redriveCount')!r}"
    )
    assert failed["error"] == "SimRedriveProbe", f"execution error {failed['error']!r}"

    sfn.redrive_execution(executionArn=exec_arn)
    token2, task_input2 = _poll_activity_task(ctx, activity_arn)
    assert task_input2 == {"rc": 1, "before": 0}, (
        f"the redriven run's activity input was {task_input2!r}: RedriveCount must read 1 in the "
        f"re-entered state, while the not-re-run Stamp state's value stays 0"
    )
    sfn.send_task_success(taskToken=token2, output=json.dumps({"ok": True}))
    done = _wait_status(ctx, exec_arn, lambda s: s not in ("RUNNING", "FAILED"))
    assert done["status"] == "SUCCEEDED", (
        f"redriven execution {done['status']!r}: {done.get('error')!r} {done.get('cause')!r}"
    )
    assert done["redriveCount"] == 1, f"DescribeExecution redriveCount {done.get('redriveCount')!r}"

    out = json.loads(done["output"])
    expected = {"orig": True, "before": {"rc": 0}, "work": {"ok": True}, "after": {"rc": 1}, "nata": 1}
    assert out == expected, f"final output {out!r}, expected {expected!r}"
    assert out["after"]["rc"] == out["nata"] == done["redriveCount"], (
        f"the context object's RedriveCount ($$ {out['after']['rc']!r}, $states.context "
        f"{out['nata']!r}) disagrees with DescribeExecution's {done['redriveCount']!r}"
    )

    events = _history(ctx, exec_arn)
    redriven = [e["executionRedrivenEventDetails"]["redriveCount"] for e in events
                if e["type"] == "ExecutionRedriven"]
    assert redriven == [1], f"ExecutionRedriven events carry redriveCount {redriven!r}"
    stamped = [e for e in events if e["type"] == "PassStateEntered"
               and e["stateEnteredEventDetails"]["name"] == "Stamp"]
    assert len(stamped) == 1, f"Stamp was entered {len(stamped)!r} times; a redrive must not re-run it"


# ===== helpers =====
def _tags_kv():
    return [{"Key": "sim2real", "Value": CHECK}]


def _create_role(ctx):
    """A bare execution role: activity tasks and Pass states need no permissions."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnj-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav sfn context-object execution role", Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_activity(ctx):
    sfn = ctx.client("stepfunctions")
    arn = sfn.create_activity(
        name=ctx.unique_name("sim2real-behav-sfnj-act-"), tags=[{"key": "sim2real", "value": CHECK}],
    )["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))
    return arn


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnj-")
    arn = sfn.create_state_machine(
        name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD",
        tags=[{"key": "sim2real", "value": CHECK}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _poll_activity_task(ctx, activity_arn, timeout_s=90.0):
    """GetActivityTask long-polls (up to ~60 s per call); loop until a task arrives."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sfn.get_activity_task(activityArn=activity_arn, workerName="sim2real-behav")
        if resp.get("taskToken"):
            return resp["taskToken"], json.loads(resp["input"])
    raise AssertionError(f"no activity task arrived on {activity_arn!r} within {timeout_s}s")


def _wait_status(ctx, exec_arn, done, *, timeout_s=90.0, interval_s=1.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if done(last["status"]):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} did not reach the awaited status: {last!r}")


def _best_effort_stop(ctx, exec_arn):
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="cleanup", cause="sim2real cleanup")
    except ClientError as exc:
        # StopExecution is a no-op on a terminal execution; only a vanished one is not an error.
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    events, token = [], None
    while True:
        kwargs = {"executionArn": exec_arn, "maxResults": 1000}
        if token:
            kwargs["nextToken"] = token
        page = sfn.get_execution_history(**kwargs)
        events.extend(page["events"])
        token = page.get("nextToken")
        if not token:
            return events


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
