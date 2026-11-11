"""get-activity-task-long-poll-worker-limit."""
from __future__ import annotations

import json
import time

from botocore.config import Config

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-activity-task-long-poll-worker-limit"
GROUP = 'activities'
SERVICES = ['stepfunctions']


def _role_arn(ctx):
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
        roleArn=_role_arn(ctx),
        type=sm_type,
        tags=[{"key": "sim2real-behav", "value": "true"}],
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


def _create_activity(ctx, *, name=None):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-act-")
    arn = sfn.create_activity(
        name=name, tags=[{"key": "sim2real-behav", "value": "true"}]
    )["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))
    return {"name": name, "arn": arn}


def _asl_activity_task(activity_arn, timeout_seconds=300):
    return {
        "Comment": "behavioral-activity",
        "StartAt": "T",
        "States": {
            "T": {
                "Type": "Task",
                "Resource": activity_arn,
                "TimeoutSeconds": timeout_seconds,
                "End": True,
            }
        },
    }


def _poll_activity_task(ctx, activity_arn, *, timeout_s=65):
    """GetActivityTask long-polls up to ~60s server-side; retry the call if it comes back empty."""
    client = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = client.get_activity_task(activityArn=activity_arn)
        if last.get("taskToken"):
            return last
        time.sleep(0.5)
    raise AssertionError(f"activity task not scheduled within {timeout_s}s: {last!r}")


def _run_concurrent(fns, *, timeout_s=90):
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:
            results[idx] = exc
        resolved.add(idx)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


def _budget_s(ctx, cap_s):
    """A wait's timeout, bounded by the runner's remaining time so the wait fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


# timing:real-time — lease: 60 s https://docs.aws.amazon.com/step-functions/latest/apireference/API_GetActivityTask.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Twenty concurrent GetActivityTask long-polls on one activity with no task scheduled are all
    accepted without ActivityWorkerLimitExceeded and return no token; a later poller still
    receives a scheduled task and the execution succeeds."""
    sfn = ctx.client("stepfunctions")
    # A single retry re-runs the ~60s server-side long poll from scratch, which can make a
    # transient, unrelated throttle on the shared account masquerade as a worker-limit refusal.
    # Retries off surfaces each call's true outcome within one long-poll window.
    burst_sfn = ctx.client("stepfunctions", config=Config(retries={"max_attempts": 1}))
    act = _create_activity(ctx)

    num_pollers = 20
    burst = _run_concurrent(
        [lambda: burst_sfn.get_activity_task(activityArn=act["arn"]) for _ in range(num_pollers)],
        timeout_s=_budget_s(ctx, 200),
    )
    errors = [r for r in burst if isinstance(r, BaseException)]
    assert not errors, (
        f"expected all {num_pollers} concurrent long-polling workers against one activity to be "
        f"accepted (no ActivityWorkerLimitExceeded), got {len(errors)} failures: {errors}"
    )
    with_token = [r for r in burst if r.get("taskToken")]
    assert not with_token, (
        f"expected no task token from any of the {num_pollers} pollers (none was scheduled), "
        f"got {len(with_token)}: {with_token}"
    )

    sm_arn = _create_state_machine(ctx, _asl_activity_task(act["arn"]))
    exec_arn = _start_execution(ctx, sm_arn)
    task = _poll_activity_task(ctx, act["arn"], timeout_s=_budget_s(ctx, 30))
    assert task.get("taskToken"), (
        f"expected the activity to still serve a real scheduled task to a fresh poller after "
        f"the {num_pollers}-worker burst, got {task}"
    )
    sfn.send_task_success(taskToken=task["taskToken"], output="{}")
    final = _wait_execution_complete(ctx, exec_arn, timeout_s=_budget_s(ctx, 30))
    assert final["status"] == "SUCCEEDED", f"expected SUCCEEDED via the post-burst poller, got {final}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
