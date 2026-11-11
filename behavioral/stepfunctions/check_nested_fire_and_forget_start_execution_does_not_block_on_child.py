"""nested-fire-and-forget-start-execution-does-not-block-on-child."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nested-fire-and-forget-start-execution-does-not-block-on-child"
GROUP = 'task_integrations'
SERVICES = ['stepfunctions']

_CHILD_WAIT_SECONDS = 8
_CHILD_OUTPUT = {"computed": True, "value": 42}


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A plain (non-.sync) states:startExecution Task returns the raw StartExecution SDK response
    (ExecutionArn, StartDate, Sdk*Metadata) with none of the child's result, and the parent stops
    before the delayed child does.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/connect-stepfunctions.html
    """
    role_arn = _create_sfn_role(ctx)
    child_arn = _create_state_machine(ctx, {
        "Comment": "a child slow enough that a blocking caller could not finish before it does",
        "StartAt": "Delay",
        "States": {
            "Delay": {"Type": "Wait", "Seconds": _CHILD_WAIT_SECONDS, "Next": "Compute"},
            "Compute": {"Type": "Pass", "Parameters": _CHILD_OUTPUT, "End": True},
        },
    }, name_prefix="sim2real-behav-fnf-child-")

    role_arn = _authorize_start_execution(ctx, role_arn, child_arn)
    parent_arn = _create_state_machine(ctx, {
        "Comment": "fire-and-forget the child, never wait for it",
        "StartAt": "InvokeChild",
        "States": {
            "InvokeChild": {
                "Type": "Task",
                "Resource": "arn:aws:states:::states:startExecution",
                "Parameters": {"StateMachineArn": child_arn, "Input": {"trigger": "fnf"}},
                "End": True,
            }
        },
    }, role_arn=role_arn, name_prefix="sim2real-behav-fnf-parent-")

    parent = _run_to_terminal(ctx, parent_arn, {})
    assert parent["status"] == "SUCCEEDED", (
        f"the parent execution was {parent['status']!r}: "
        f"{parent.get('error')!r} {parent.get('cause')!r}"
    )

    output = json.loads(parent["output"])
    assert {"ExecutionArn", "StartDate"} <= output.keys(), (
        f"expected ExecutionArn and StartDate in the task result, got keys {sorted(output)!r}"
    )
    # Not an optimized integration like .sync, so the literal SDK response comes back.
    assert "SdkHttpMetadata" in output and "SdkResponseMetadata" in output, (
        f"expected the raw StartExecution SDK response envelope (SdkHttpMetadata, "
        f"SdkResponseMetadata) — this integration is not reshaped the way .sync is; got keys "
        f"{sorted(output)!r}"
    )
    assert "Status" not in output and "Output" not in output, (
        f"a fire-and-forget start must carry none of the child's eventual result, got "
        f"{output!r}"
    )
    assert "SUCCEEDED" not in json.dumps(output), (
        f"the parent's own task result mentions the child's terminal status: {output!r}"
    )
    assert isinstance(output["StartDate"], int) and output["StartDate"] > 0, (
        f"expected StartDate as a raw epoch-millis integer, got {output['StartDate']!r}"
    )

    children = _executions(ctx, child_arn)
    assert len(children) == 1, (
        f"the child ran {len(children)!r} executions, expected exactly the one the parent "
        f"started: {[c['name'] for c in children]!r}"
    )
    assert output["ExecutionArn"] == children[0]["executionArn"], (
        f"the task result named {output['ExecutionArn']!r}, but the child's actual execution "
        f"is {children[0]['executionArn']!r}"
    )

    child = _wait_terminal(ctx, children[0]["executionArn"], timeout_s=60)
    assert child["status"] == "SUCCEEDED", (
        f"the child execution the parent fired ended {child['status']!r}: "
        f"{child.get('error')!r} {child.get('cause')!r}"
    )
    assert json.loads(child["output"]) == _CHILD_OUTPUT, (
        f"the child's own output was {child['output']!r}, expected {_CHILD_OUTPUT!r}"
    )
    assert parent["stopDate"] < child["stopDate"], (
        f"the parent (stopped {parent['stopDate']!r}) did not finish before the child it fired "
        f"(stopped {child['stopDate']!r}) — the parent should be long terminal while the "
        f"child is still running its own Wait state"
    )


_TRUST_RACE_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "is not authorized to perform",
    "States.Permissions",
    "States.TaskFailed",
    "AccessDeniedException",
)


def _create_sfn_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-fnfrole-")
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
        Description="sim2real-behav sfn fire-and-forget execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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


def _authorize_start_execution(ctx, role_arn, child_arn):
    iam = ctx.client("iam")
    role_name = role_arn.rsplit("/", 1)[-1]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="inline",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "states:StartExecution", "Resource": child_arn},
            ],
        }),
    )
    # IAM propagation exposes no condition to poll — the bounded retry in _run_to_terminal,
    # which uses a fresh execution per attempt, is what absorbs it.
    return role_arn


def _create_state_machine(ctx, definition, *, role_arn=None, name_prefix="sim2real-behav-sm-"):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name(name_prefix)
    role_arn = role_arn or _create_sfn_role(ctx)
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD",
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


def _start_execution(ctx, sm_arn, input_data):
    sfn = ctx.client("stepfunctions")
    arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
        input=json.dumps(input_data),
    )["executionArn"]
    ctx.on_cleanup(lambda a=arn: _best_effort_stop(ctx, a))
    return arn


def _best_effort_stop(ctx, exec_arn):
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="cleanup", cause="sim2real cleanup"
        )
    except ClientError as exc:
        # StopExecution is a no-op on a terminal execution; only a vanished one is not an error.
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _wait_terminal(ctx, exec_arn, *, timeout_s=90):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(1.0)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _run_to_terminal(ctx, sm_arn, input_data, *, timeout_s=60, attempts=6):
    """Start an execution and poll to terminal, absorbing IAM propagation at first use of the
    role's states:StartExecution grant only — a fresh execution per attempt, never a sleep.
    """
    desc = None
    for _ in range(attempts):
        exec_arn = _start_execution(ctx, sm_arn, input_data)
        desc = _wait_terminal(ctx, exec_arn, timeout_s=timeout_s)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _TRUST_RACE_MARKERS):
            return desc
        time.sleep(5)
    return desc


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
