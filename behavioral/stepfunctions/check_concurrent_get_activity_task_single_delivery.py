"""concurrent-get-activity-task-single-delivery."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-get-activity-task-single-delivery"
GROUP = 'activities'
SERVICES = ['stepfunctions']


_ROLE_ARNS = {}


def _execution_role_arn(ctx):
    """Create one Step Functions execution role per check run and register its cleanup."""
    key = id(ctx)
    if key in _ROLE_ARNS:
        return _ROLE_ARNS[key]
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
    ctx.on_cleanup(lambda: _ROLE_ARNS.pop(key, None))
    _ROLE_ARNS[key] = arn
    return arn


def _create_sm_retrying(sfn, **kwargs):
    """CreateStateMachine, retried while a just-created role is still propagating in IAM."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return sfn.create_state_machine(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    arn = _create_sm_retrying(
        sfn,
        name=name,
        definition=json.dumps(definition),
        roleArn=_execution_role_arn(ctx),
        type=sm_type,
        tags=[{"key": "sim2real", "value": CHECK}],
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
    arn = sfn.create_activity(name=name, tags=[{"key": "sim2real", "value": CHECK}])["activityArn"]
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


def _run_concurrent(fns, *, timeout_s=60):
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
    """One scheduled activity task is delivered to exactly one of several concurrent GetActivityTask
    pollers; the others return without a token and the execution succeeds on that one token."""
    # GetActivityTask long-polls server-side for up to ~60s, right at the botocore client's
    # default 60s read_timeout -- a poller whose server-side wait lands near that boundary can
    # race a ReadTimeoutError and silently retry, pushing its wall-clock past the concurrent-run
    # budget below. Widen the read timeout past the long-poll ceiling and drop retries before the
    # first ctx.client("stepfunctions") call -- Context caches one client per service.
    from botocore.config import Config

    ctx._config = ctx._config.merge(Config(read_timeout=75, retries={"max_attempts": 1}))

    sfn = ctx.client("stepfunctions")
    act = _create_activity(ctx)
    sm_arn = _create_state_machine(ctx, _asl_activity_task(act["arn"]))
    exec_arn = _start_execution(ctx, sm_arn)

    client = ctx.client("stepfunctions")
    n = 5
    results = _run_concurrent(
        [lambda: client.get_activity_task(activityArn=act["arn"]) for _ in range(n)], timeout_s=_budget_s(ctx, 90)
    )
    successes = [r for r in results if not isinstance(r, BaseException)]
    assert len(successes) == n, f"expected all {n} pollers to get a (possibly empty) response, got: {results}"
    with_token = [r for r in successes if r.get("taskToken")]
    assert len(with_token) == 1, f"expected exactly one poller to receive the task, got {len(with_token)}: {results}"

    # Clean up the outstanding task so it doesn't linger as an unfinished execution.
    sfn.send_task_success(taskToken=with_token[0]["taskToken"], output="{}")
    final = _wait_execution_complete(ctx, exec_arn, timeout_s=_budget_s(ctx, 60))
    assert final["status"] == "SUCCEEDED", (
        f"expected the execution to reach SUCCEEDED via the single delivered task, got: {final}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
