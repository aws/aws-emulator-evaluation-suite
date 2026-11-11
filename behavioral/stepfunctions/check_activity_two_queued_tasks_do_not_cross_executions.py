"""activity-two-queued-tasks-do-not-cross-executions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "activity-two-queued-tasks-do-not-cross-executions"
GROUP = 'activities'
SERVICES = ['stepfunctions']

#: Two executions of ONE state machine, queueing two tasks on ONE activity. The tag is how each
#: leg is identified on the way out (the worker's `input`) and on the way back (the execution's
#: `output`), which is what makes a crossed reply detectable rather than merely unlikely.
_LEGS = ("alpha", "beta")
_TASK_TIMEOUT_SECONDS = 180


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two tasks queued on one activity by two concurrent executions get DISTINCT tokens, and each
    worker's reply lands in the execution that queued its task, never in the sibling; delivery
    order is not asserted, as AWS does not guarantee it.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    activity_arn = _create_activity(ctx)
    definition = {
        "Comment": "one activity task; two concurrent executions queue one each",
        "StartAt": "HandOff",
        "States": {
            "HandOff": {
                "Type": "Task",
                "Resource": activity_arn,
                "TimeoutSeconds": _TASK_TIMEOUT_SECONDS,
                "End": True,
            }
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn)

    # Start both legs before either is served, so both tasks really are queued at once.
    exec_arns = {leg: _start_execution(ctx, sm_arn, {"leg": leg}) for leg in _LEGS}

    # Collect one task per leg. Each poll is a fresh long poll; which leg it returns is the
    # service's choice and is not asserted.
    tasks = []
    for _ in _LEGS:
        tasks.append(_poll_activity_task(
            ctx, activity_arn, worker_name=ctx.unique_name("sim2real-behav-worker-")
        ))

    tokens = [t["taskToken"] for t in tasks]
    assert len(set(tokens)) == len(_LEGS), (
        f"{len(_LEGS)!r} queued tasks were handed out under only {len(set(tokens))!r} distinct "
        f"task tokens — one token for two tasks makes the two executions indistinguishable to "
        f"the worker"
    )

    delivered_legs = [json.loads(t["input"])["leg"] for t in tasks]
    assert sorted(delivered_legs) == sorted(_LEGS), (
        f"the workers were handed legs {sorted(delivered_legs)!r}; the two executions queued "
        f"exactly {sorted(_LEGS)!r}, so every queued input must be delivered once and only once"
    )

    # Reply under each token with a payload that names the leg that token carried. A target that
    # routes a reply to the wrong execution now produces an output naming the other leg.
    replies = {}
    for task in tasks:
        leg = json.loads(task["input"])["leg"]
        replies[leg] = {"echo": leg, "token_sha_len": len(task["taskToken"])}
        sfn.send_task_success(taskToken=task["taskToken"], output=json.dumps(replies[leg]))

    for leg in _LEGS:
        final = _wait_terminal(ctx, exec_arns[leg], timeout_s=120)
        assert final["status"] == "SUCCEEDED", (
            f"the {leg!r} execution ended {final['status']!r} after its worker replied: "
            f"{final.get('error')!r} / {final.get('cause')!r}"
        )
        output = json.loads(final["output"])
        assert output == replies[leg], (
            f"the {leg!r} execution's output was {output!r}; it must be exactly the reply sent "
            f"under the token that carried the {leg!r} input, {replies[leg]!r}"
        )
        # The absence half: the sibling's reply must not appear here. Equality above implies it,
        # but a crossed reply is the specific defect this check exists to detect, so it is
        # asserted in its own right with its own message.
        other = [x for x in _LEGS if x != leg]
        assert output["echo"] not in other, (
            f"the {leg!r} execution's output echoes {output['echo']!r} — a sibling execution's "
            f"reply was routed into it"
        )


# ===== helpers =====
def _create_sfn_role(ctx):
    """A states.amazonaws.com-assumable execution role with no permissions attached: an Activity
    task needs none, because the worker calls SendTaskSuccess with its own credentials."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Description="sim2real-behav sfn activity execution role",
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    return role_arn


def _create_activity(ctx):
    sfn = ctx.client("stepfunctions")
    arn = sfn.create_activity(
        name=ctx.unique_name("sim2real-behav-act-"),
        tags=[{"key": "sim2real", "value": "1"}],
    )["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))
    return arn


def _create_state_machine(ctx, definition, role_arn, *, sm_type="STANDARD"):
    """CreateStateMachine, retrying AccessDeniedException while the fresh role propagates (IAM
    exposes no condition to poll for that)."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type=sm_type,
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last!r}")


def _start_execution(ctx, sm_arn, input_payload):
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn,
        name=ctx.unique_name("sim2real-behav-exec-"),
        input=json.dumps(input_payload),
    )["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, exec_arn))
    return exec_arn


def _best_effort_stop(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    try:
        sfn.stop_execution(executionArn=exec_arn, error="cleanup", cause="sim2real cleanup")
    except ClientError as exc:
        # StopExecution is a no-op on a terminal execution; only a vanished one is not an error.
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _poll_activity_task(ctx, activity_arn, *, worker_name, timeout_s=120.0):
    """GetActivityTask long-polls ~60 s server-side and returns empty on expiry; re-call it."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.get_activity_task(activityArn=activity_arn, workerName=worker_name)
        if last.get("taskToken"):
            return last
        time.sleep(0.5)
    raise AssertionError(
        f"no activity task was ever handed to a worker within {timeout_s}s; last poll {last!r}"
    )


def _wait_terminal(ctx, exec_arn, *, timeout_s=120.0, interval_s=1.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
