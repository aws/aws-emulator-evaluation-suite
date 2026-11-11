"""redrive-execution-preserves-original-history-order."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redrive-execution-preserves-original-history-order"
GROUP = "ordering"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """After RedriveExecution, GetExecutionHistory keeps the original events in order
    and appends the new (redrive) events strictly after the last original event id."""
    sfn = ctx.client("stepfunctions")

    activity_arn = sfn.create_activity(name=ctx.unique_name("sim2real-behav-act-"))["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=activity_arn))

    role_arn = _create_sfn_role(ctx)
    definition = json.dumps(
        {
            "Comment": "single activity task, no retry/catch",
            "StartAt": "DoTask",
            "States": {"DoTask": {"Type": "Task", "Resource": activity_arn, "End": True}},
        }
    )
    name = ctx.unique_name("sim2real-behav-redrivehist-")
    sm_arn = _create_state_machine(ctx, sfn, name, definition, role_arn)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("exec-"), input="{}"
    )["executionArn"]

    task_token = _get_task_token(sfn, activity_arn)
    sfn.send_task_failure(taskToken=task_token, error="InducedFailure", cause="behavioral test")

    _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn)["status"],
        lambda s: s == "FAILED",
        timeout_s=30.0,
        interval_s=1.0,
    )

    history_before = _get_full_history(sfn, exec_arn)
    ids_before = [e["id"] for e in history_before]
    assert ids_before == sorted(ids_before), (
        f"original history is not in ascending id order: {ids_before}"
    )
    assert len(ids_before) >= 3, (
        f"expected at least Start/Failed events in original history, got {len(ids_before)}: {ids_before}"
    )
    last_original_id = ids_before[-1]

    sfn.redrive_execution(executionArn=exec_arn)

    _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn)["status"],
        lambda s: s == "RUNNING",
        timeout_s=30.0,
        interval_s=1.0,
    )

    task_token_2 = _get_task_token(sfn, activity_arn)
    sfn.send_task_success(taskToken=task_token_2, output="{}")

    _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn)["status"],
        lambda s: s == "SUCCEEDED",
        timeout_s=30.0,
        interval_s=1.0,
    )

    history_after = _get_full_history(sfn, exec_arn)
    ids_after = [e["id"] for e in history_after]

    assert len(history_after) > len(history_before), (
        f"redrive did not append any new events: before={len(history_before)}, after={len(history_after)}"
    )
    # Original events must be an exact, unmodified, order-preserved prefix.
    prefix = history_after[: len(history_before)]
    assert [e["id"] for e in prefix] == ids_before, (
        f"original event ids were altered/reordered: expected={ids_before}, "
        f"actual={[e['id'] for e in prefix]}"
    )
    assert [e["type"] for e in prefix] == [e["type"] for e in history_before], (
        f"original event types were altered: expected={[e['type'] for e in history_before]}, "
        f"actual={[e['type'] for e in prefix]}"
    )
    # New events must all sort strictly after the last original event.
    new_ids = ids_after[len(history_before):]
    assert all(i > last_original_id for i in new_ids), (
        f"new events not appended after original tail: last_original={last_original_id}, new={new_ids}"
    )
    assert new_ids == sorted(new_ids), (
        f"appended redrive events are not in ascending order: {new_ids}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_sfn_role(ctx, extra_statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    statements = list(extra_statements or [])
    if not statements:
        statements = [{"Effect": "Allow", "Action": "states:DescribeExecution", "Resource": "*"}]
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_state_machine(ctx, sfn, name, definition, role_arn, type_="STANDARD"):
    deadline = time.monotonic() + 60.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn, type=type_
            )
            return resp["stateMachineArn"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "AccessDeniedException":
                last_err = exc
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"could not create state machine after IAM propagation wait: {last_err}")


def _get_task_token(sfn, activity_arn, attempts=3):
    for _ in range(attempts):
        resp = sfn.get_activity_task(activityArn=activity_arn)
        if resp.get("taskToken"):
            return resp["taskToken"]
    raise AssertionError("no activity task became available")


def _get_full_history(sfn, execution_arn):
    events = []
    token = None
    while True:
        kwargs = {"executionArn": execution_arn, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = sfn.get_execution_history(**kwargs)
        events.extend(resp["events"])
        token = resp.get("nextToken")
        if not token:
            break
    return events


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
