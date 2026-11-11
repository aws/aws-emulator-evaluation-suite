"""sfn-nested-sync-child-execution-output-is-returned-to-the-parent."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-nested-sync-child-execution-output-is-returned-to-the-parent"
GROUP = 'task_integrations'
SERVICES = ['stepfunctions']

_PARTS = ["alpha", "beta", "gamma"]


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c3")
def run(ctx) -> None:
    """A states:startExecution.sync:2 task blocks on a child state machine and returns the
    child's own computed Output to the parent as the task result.
    """
    sfn = ctx.client("stepfunctions")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    child_definition = {
        "Comment": "compute a value from the parent-supplied input",
        "StartAt": "Compute",
        "States": {
            "Compute": {
                "Type": "Pass",
                "Parameters": {
                    "value.$": "States.Format('{}::{}', $.seed, States.ArrayLength($.parts))"
                },
                "End": True,
            }
        },
    }
    # The child needs no permissions of its own — a Pass state calls nothing.
    _child_role_name, child_role_arn = _create_sfn_role(
        ctx, [{"Effect": "Allow", "Action": "states:DescribeExecution", "Resource": "*"}]
    )
    child_arn = _create_state_machine(
        ctx, child_definition, child_role_arn, name_prefix="sim2real-behav-child-"
    )

    # The parent's role is what `.sync:2` runs the child under, plus the managed EventBridge
    # rule the .sync integrations use to learn that the child finished.
    _parent_role_name, parent_role_arn = _create_sfn_role(ctx, [
        {"Effect": "Allow", "Action": "states:StartExecution", "Resource": child_arn},
        {
            "Effect": "Allow",
            "Action": ["states:DescribeExecution", "states:StopExecution"],
            "Resource": f"arn:aws:states:{ctx.region}:{account_id}:execution:*:*",
        },
        {
            "Effect": "Allow",
            "Action": ["events:PutTargets", "events:PutRule", "events:DescribeRule"],
            "Resource": (
                f"arn:aws:events:{ctx.region}:{account_id}:rule/"
                "StepFunctionsGetEventsForStepFunctionsExecutionRule"
            ),
        },
    ])
    parent_definition = {
        "Comment": "block on the child and keep only its computed value",
        "StartAt": "CallChild",
        "States": {
            "CallChild": {
                "Type": "Task",
                "Resource": "arn:aws:states:::states:startExecution.sync:2",
                "Parameters": {
                    "StateMachineArn": child_arn,
                    "Input": {"seed.$": "$.seed", "parts.$": "$.parts"},
                },
                "ResultSelector": {"fromChild.$": "$.Output.value"},
                "End": True,
            }
        },
    }
    parent_arn = _create_state_machine(ctx, parent_definition, parent_role_arn)

    seed = ctx.unique_name("seed-")
    expected = f"{seed}::{len(_PARTS)}"
    parent = _run_to_terminal(ctx, parent_arn, {"seed": seed, "parts": _PARTS}, timeout_s=180.0)
    assert parent["status"] == "SUCCEEDED", (
        f'the parent execution was {parent["status"]!r}: '
        f'{parent.get("error")!r} {parent.get("cause")!r}'
    )

    child_executions = _executions(ctx, child_arn)
    assert len(child_executions) == 1, (
        f"CHILD ran {len(child_executions)!r} executions, expected exactly the one the parent "
        f'started: {[e["name"] for e in child_executions]!r}'
    )
    child = sfn.describe_execution(executionArn=child_executions[0]["executionArn"])
    assert child["status"] == "SUCCEEDED", (
        f'the child execution was {child["status"]!r}: '
        f'{child.get("error")!r} {child.get("cause")!r}'
    )

    parent_output = json.loads(parent["output"])
    assert parent_output["fromChild"] == expected, (
        f"the parent output was {parent_output!r}, expected fromChild={expected!r} — the value "
        f"the child's interpreter computes from the seed the parent passed it"
    )
    assert parent_output["fromChild"] == json.loads(child["output"])["value"], (
        f'the parent saw {parent_output!r} but the child produced {child["output"]!r}'
    )
    assert child["stopDate"] <= parent["stopDate"], (
        f'the parent did not wait for the child: child stopped at {child["stopDate"]!r}, '
        f'parent at {parent["stopDate"]!r}'
    )


def _create_sfn_role(ctx, statements):
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
        Description="sim2real-behav sfn execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_name = f"{role_name}-policy"

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    # IAM propagation exposes no condition to poll; the bounded retries in _create_state_machine
    # and _run_to_terminal absorb it.
    return role_name, role_arn


def _create_state_machine(ctx, definition, role_arn, *, sm_type="STANDARD",
                          name_prefix="sim2real-behav-sm-"):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name(name_prefix)
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type=sm_type,
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the role: {last!r}")


_TRUST_RACE_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "is not authorized to perform: sts:AssumeRole",
    "States.Permissions",
    "AccessDeniedException",
)


def _run_to_terminal(ctx, sm_arn, input_payload, *, timeout_s=120.0, max_attempts=6):
    """Start an execution and poll to terminal, retrying with a fresh execution (bounded) while
    an unpropagated states:StartExecution grant fails the parent with States.Permissions."""
    sfn = ctx.client("stepfunctions")
    desc = None
    for _ in range(max_attempts):
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn,
            name=ctx.unique_name("sim2real-behav-exec-"),
            input=json.dumps(input_payload),
        )["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: _best_effort_stop(ctx, a))
        desc = _wait_terminal(ctx, exec_arn, timeout_s=timeout_s)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _TRUST_RACE_MARKERS):
            return desc
        time.sleep(5)
    return desc


def _wait_terminal(ctx, exec_arn, *, timeout_s=120.0, interval_s=1.5):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


def _best_effort_stop(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    try:
        sfn.stop_execution(executionArn=exec_arn, error="cleanup", cause="sim2real cleanup")
    except ClientError as exc:
        # StopExecution is a no-op on a terminal execution; only a vanished one is not an error.
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _executions(ctx, sm_arn):
    """Every execution of this state machine, paginated."""
    sfn = ctx.client("stepfunctions")
    out, token = [], None
    while True:
        kwargs = {"stateMachineArn": sm_arn, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = sfn.list_executions(**kwargs)
        out.extend(resp["executions"])
        token = resp.get("nextToken")
        if not token:
            return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
