"""sfn-startexecution-integration-child-started-by-alias-or-version-arn."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-startexecution-integration-child-started-by-alias-or-version-arn"
GROUP = "task_integrations"
SERVICES = ["stepfunctions"]

_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")


def _account(ctx):
    return ctx.account


def _create_role(ctx, principal, statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnver-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": principal},
                       "Action": "sts:AssumeRole"}],
    })
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust,
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
    if statements:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
    return role_arn


def _create_state_machine(ctx, definition, role_arn, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type=sm_type,
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the role: {last!r}")


def _best_effort_stop(ctx, exec_arn):
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="SimCleanup", cause="sim2real cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _start(ctx, sm_arn, payload=None):
    arn = ctx.client("stepfunctions").start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
        input=json.dumps(payload or {}),
    )["executionArn"]
    ctx.on_cleanup(lambda a=arn: _best_effort_stop(ctx, a))
    return arn


def _poll(probe, predicate, *, timeout_s, what, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what}: not reached within {timeout_s}s; last={last!r}")


def _executions(ctx, sm_arn):
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


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
    "cap:c3",
)
def run(ctx) -> None:
    """A parent's states:startExecution.sync Task targeting a child by its version ARN, then by
    an alias ARN, starts child executions whose DescribeExecution carries stateMachineVersionArn
    and stateMachineAliasArn exactly as a direct StartExecution call would.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/connect-stepfunctions.html
    """
    sfn = ctx.client("stepfunctions")
    account = _account(ctx)
    child_name = ctx.unique_name("sim2real-behav-verchild-")
    child_role = _create_role(ctx, "states.amazonaws.com", [])
    child_arn = _create_state_machine(
        ctx, {"StartAt": "P", "States": {"P": {"Type": "Pass",
                                                "Parameters": {"via": "child"}, "End": True}}},
        child_role, name=child_name,
    )

    v1 = sfn.publish_state_machine_version(stateMachineArn=child_arn)["stateMachineVersionArn"]
    alias_name = ctx.unique_name("sim2real-behav-alias-")
    sfn.create_state_machine_alias(
        name=alias_name, routingConfiguration=[{"stateMachineVersionArn": v1, "weight": 100}],
    )
    alias_arn = f"{child_arn}:{alias_name}"

    def _delete_alias():
        sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn)

    ctx.on_cleanup(_delete_alias)

    parent_role = _create_role(ctx, "states.amazonaws.com", [
        {"Effect": "Allow", "Action": "states:StartExecution",
         "Resource": child_arn},
        {"Effect": "Allow", "Action": ["states:DescribeExecution", "states:StopExecution"],
         "Resource": f"arn:aws:states:{ctx.region}:{account}:execution:{child_name}:*"},
        {"Effect": "Allow", "Action": ["events:PutTargets", "events:PutRule", "events:DescribeRule"],
         "Resource": f"arn:aws:events:{ctx.region}:{account}:rule/"
                     "StepFunctionsGetEventsForStepFunctionsExecutionRule"},
    ])
    parent_arn = _create_state_machine(ctx, {
        "StartAt": "ByVersion",
        "States": {
            "ByVersion": {
                "Type": "Task",
                "Resource": "arn:aws:states:::states:startExecution.sync:2",
                "Parameters": {"StateMachineArn": v1, "Input": {"which": "version"}},
                "Next": "ByAlias",
            },
            "ByAlias": {
                "Type": "Task",
                "Resource": "arn:aws:states:::states:startExecution.sync:2",
                "Parameters": {"StateMachineArn": alias_arn, "Input": {"which": "alias"}},
                "End": True,
            },
        },
    }, parent_role)

    parent_exec = _start(ctx, parent_arn, {})
    done = _poll(lambda: sfn.describe_execution(executionArn=parent_exec),
                 lambda d: d["status"] in _TERMINAL, timeout_s=90, what="parent terminal")
    assert done["status"] == "SUCCEEDED", (
        f"the parent calling the child by version then alias ARN ended {done['status']!r}: "
        f"{done.get('error')!r} {done.get('cause')!r}"
    )

    children = _poll(lambda: _executions(ctx, child_arn), lambda cs: len(cs) == 2,
                      timeout_s=30, what="two child executions listed")
    children = sorted(children, key=lambda c: c["startDate"])
    by_version = sfn.describe_execution(executionArn=children[0]["executionArn"])
    by_alias = sfn.describe_execution(executionArn=children[1]["executionArn"])

    assert by_version.get("stateMachineVersionArn") == v1, (
        f"a child started by version ARN must carry stateMachineVersionArn={v1!r}, "
        f"got {by_version.get('stateMachineVersionArn')!r}"
    )
    assert "stateMachineAliasArn" not in by_version, (
        f"a child started by version ARN directly must carry no stateMachineAliasArn, "
        f"got {by_version.get('stateMachineAliasArn')!r}"
    )
    assert by_alias.get("stateMachineAliasArn") == alias_arn, (
        f"a child started by alias ARN must carry stateMachineAliasArn={alias_arn!r}, "
        f"got {by_alias.get('stateMachineAliasArn')!r}"
    )
    assert by_alias.get("stateMachineVersionArn") == v1, (
        f"a child started by alias ARN must resolve stateMachineVersionArn={v1!r}, "
        f"got {by_alias.get('stateMachineVersionArn')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
