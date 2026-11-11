"""parallel-result-ordering-and-sibling-branch-abort."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "parallel-result-ordering-and-sibling-branch-abort"
GROUP = 'parallel_state'
SERVICES = ['stepfunctions']


def _create_sfn_role(ctx):
    """Create an execution role Step Functions may assume, deleted at cleanup."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
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
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _call_once_role_assumable(create, **kwargs):
    """Call ``create``, retrying while a just-created role is not yet assumable."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return create(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    arn = _call_once_role_assumable(
        sfn.create_state_machine,
        name=name,
        definition=json.dumps(definition),
        roleArn=_create_sfn_role(ctx),
        type=sm_type,
        tags=[{"key": "sim2real", "value": "1"}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _start_execution(ctx, sm_arn, *, input_data=None, name=None):
    sfn = ctx.client("stepfunctions")
    kwargs = {"stateMachineArn": sm_arn}
    if input_data is not None:
        kwargs["input"] = json.dumps(input_data)
    if name is not None:
        kwargs["name"] = name
    exec_arn = sfn.start_execution(**kwargs)["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    return exec_arn


def _wait_execution_complete(ctx, exec_arn, *, timeout_s=30):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(0.5)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _get_output(resp):
    raw = resp.get("output")
    return None if raw is None else json.loads(raw)


def _get_history_events(ctx, exec_arn, *, reverse=False):
    sfn = ctx.client("stepfunctions")
    events = []
    kwargs = {"executionArn": exec_arn, "reverseOrder": reverse}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        events.extend(resp["events"])
        if "nextToken" not in resp:
            break
        kwargs["nextToken"] = resp["nextToken"]
    return events


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Parallel output[i] is branch i's result regardless of completion order, and a failing
    branch aborts its still-running siblings instead of waiting for them to finish.
    """
    # Staggered Waits make completion order (b2, b3, b1) differ from definition order.
    ordering_def = {
        "StartAt": "Fan",
        "States": {
            "Fan": {
                "Type": "Parallel",
                "Branches": [
                    {
                        "StartAt": "SlowWait",
                        "States": {
                            "SlowWait": {"Type": "Wait", "Seconds": 4, "Next": "Slow"},
                            "Slow": {"Type": "Pass", "Result": "b1", "End": True},
                        },
                    },
                    {
                        "StartAt": "Fast",
                        "States": {"Fast": {"Type": "Pass", "Result": "b2", "End": True}},
                    },
                    {
                        "StartAt": "MidWait",
                        "States": {
                            "MidWait": {"Type": "Wait", "Seconds": 2, "Next": "Mid"},
                            "Mid": {"Type": "Pass", "Result": "b3", "End": True},
                        },
                    },
                ],
                "End": True,
            }
        },
    }
    desc = _wait_execution_complete(
        ctx,
        _start_execution(ctx, _create_state_machine(ctx, ordering_def), input_data={}),
        timeout_s=120,
    )
    assert desc["status"] == "SUCCEEDED", (
        f"parallel ordering execution must succeed, got {desc.get('status')} "
        f"cause={desc.get('cause')}"
    )
    assert _get_output(desc) == ["b1", "b2", "b3"], (
        f"Parallel output must be ordered by branch definition position (['b1', 'b2', 'b3']) even "
        f"though the branches completed in the order b2, b3, b1; got {_get_output(desc)!r}"
    )

    # The abort shows as an Aborted event, no post-Wait state, and far less than the 20s Wait.
    abort_def = {
        "StartAt": "Fan",
        "States": {
            "Fan": {
                "Type": "Parallel",
                "Branches": [
                    {
                        "StartAt": "LongWait",
                        "States": {
                            "LongWait": {"Type": "Wait", "Seconds": 20, "Next": "SlowDone"},
                            "SlowDone": {"Type": "Pass", "Result": "never", "End": True},
                        },
                    },
                    {
                        "StartAt": "Boom",
                        "States": {
                            "Boom": {
                                "Type": "Fail",
                                "Error": "BranchBoom",
                                "Cause": "deliberate branch failure",
                            }
                        },
                    },
                ],
                "Catch": [
                    {"ErrorEquals": ["States.ALL"], "ResultPath": "$.error", "Next": "Recovered"}
                ],
                "End": True,
            },
            "Recovered": {"Type": "Pass", "End": True},
        },
    }
    abort_arn = _start_execution(
        ctx, _create_state_machine(ctx, abort_def), input_data={"seed": 1}
    )
    abort = _wait_execution_complete(ctx, abort_arn, timeout_s=120)
    assert abort["status"] == "SUCCEEDED", (
        f"the Catch must recover the failed Parallel, got {abort.get('status')} "
        f"error={abort.get('error')} cause={abort.get('cause')}"
    )
    out = _get_output(abort)
    assert out.get("seed") == 1, f"Catch ResultPath must preserve the state input, got {out!r}"
    assert out.get("error", {}).get("Error") == "BranchBoom", (
        f"the caught error must be the failing branch's error name 'BranchBoom', got {out!r}"
    )

    events = _get_history_events(ctx, abort_arn)
    types = [e["type"] for e in events]
    entered = [
        e["stateEnteredEventDetails"]["name"] for e in events if "stateEnteredEventDetails" in e
    ]
    assert "SlowDone" not in entered, (
        f"the surviving branch must be aborted mid-Wait, so 'SlowDone' must never be entered; "
        f"entered states were {entered}"
    )
    assert any(t.endswith("Aborted") for t in types), (
        f"history must record the sibling branch being aborted (a *Aborted event); types were {types}"
    )
    assert "ParallelStateFailed" in types, (
        f"history must record ParallelStateFailed before the catcher runs; types were {types}"
    )
    elapsed = (abort["stopDate"] - abort["startDate"]).total_seconds()
    assert elapsed < 15, (
        f"the execution must not wait out the aborted sibling's 20s Wait; it took {elapsed:.1f}s"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
