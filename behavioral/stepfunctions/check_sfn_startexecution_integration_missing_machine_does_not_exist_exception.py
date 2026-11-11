"""sfn-startexecution-integration-missing-machine-does-not-exist-exception."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-startexecution-integration-missing-machine-does-not-exist-exception"
GROUP = "task_integrations"
SERVICES = ["stepfunctions"]

_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")
_IAM_RACE_MARKERS = ("not authorized to assume", "cannot be assumed")
_RESULT_KEYS = ("plainErr", "syncErr", "tokenErr")


def _account(ctx):
    return ctx.account


def _create_role(ctx, principal, statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnnoex-")
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


def _run_to_clean_terminal(ctx, sm_arn, payload, *, timeout_s=90, attempts=8):
    """Start fresh executions until none of the three captured errors is an IAM-propagation
    race: only then does the output reflect the integration's own naming of the failure."""
    sfn = ctx.client("stepfunctions")
    desc = None
    for _ in range(attempts):
        arn = _start(ctx, sm_arn, payload)
        desc = _poll(lambda: sfn.describe_execution(executionArn=arn),
                     lambda d: d["status"] in _TERMINAL, timeout_s=timeout_s,
                     what=f"execution {arn} terminal")
        assert desc["status"] == "SUCCEEDED", (
            f"the parent catching every branch's error ended {desc['status']!r} instead of "
            f"SUCCEEDED: {desc.get('error')!r} {desc.get('cause')!r}"
        )
        output = json.loads(desc["output"])
        if not any(any(m in output[k]["Cause"] for m in _IAM_RACE_MARKERS) for k in _RESULT_KEYS):
            return output
        time.sleep(5)
    raise AssertionError(f"the role never finished propagating across {attempts} attempts: {desc!r}")


def _poll(probe, predicate, *, timeout_s, what, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what}: not reached within {timeout_s}s; last={last!r}")


@tags(
    "axis:rejection",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c3",
)
def run(ctx) -> None:
    """A states:startExecution Task naming a well-formed ARN of a state machine that was never
    created fails with StepFunctions.StateMachineDoesNotExistException naming the ARN in its
    Cause, identically for the plain, .sync and .waitForTaskToken integration patterns.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/connect-stepfunctions.html
    """
    account = _account(ctx)
    missing_arn = (
        f"arn:aws:states:{ctx.region}:{account}:stateMachine:"
        f"{ctx.unique_name('sim2real-behav-missing-')}"
    )
    role_arn = _create_role(ctx, "states.amazonaws.com", [
        {"Effect": "Allow", "Action": "states:StartExecution", "Resource": "*"},
        {"Effect": "Allow", "Action": ["states:DescribeExecution", "states:StopExecution"],
         "Resource": "*"},
        {"Effect": "Allow", "Action": ["events:PutTargets", "events:PutRule", "events:DescribeRule"],
         "Resource": f"arn:aws:events:{ctx.region}:{account}:rule/"
                     "StepFunctionsGetEventsForStepFunctionsExecutionRule"},
    ])

    def _attempt(resource_name, result_key, next_state):
        params = {"StateMachineArn": missing_arn, "Input": {}}
        task = {
            "Type": "Task",
            "Resource": f"arn:aws:states:::states:{resource_name}",
            "Parameters": params,
            "Catch": [{"ErrorEquals": ["States.ALL"], "ResultPath": f"$.{result_key}",
                       "Next": next_state}],
            "Next": next_state,
        }
        if resource_name.endswith("waitForTaskToken"):
            params["Input"] = {"token.$": "$$.Task.Token"}
            task["TimeoutSeconds"] = 60
        return task

    parent_arn = _create_state_machine(ctx, {
        "StartAt": "Plain",
        "States": {
            "Plain": _attempt("startExecution", "plainErr", "Sync"),
            "Sync": _attempt("startExecution.sync", "syncErr", "WaitToken"),
            "WaitToken": _attempt("startExecution.waitForTaskToken", "tokenErr", "Done"),
            "Done": {"Type": "Pass", "End": True},
        },
    }, role_arn)

    output = _run_to_clean_terminal(ctx, parent_arn, {})

    for key, resource_name in (
        ("plainErr", "startExecution"), ("syncErr", "startExecution.sync"),
        ("tokenErr", "startExecution.waitForTaskToken"),
    ):
        err = output[key]
        assert err["Error"] == "StepFunctions.StateMachineDoesNotExistException", (
            f"{resource_name} targeting a never-created state machine ARN must fail with "
            f"StepFunctions.StateMachineDoesNotExistException, got {err['Error']!r} "
            f"(cause {err['Cause']!r})"
        )
        prefix = f"State Machine Does Not Exist: '{missing_arn}' (Service: AWSStepFunctions; " \
                 f"Status Code: 400; Error Code: StateMachineDoesNotExist; Request ID: "
        assert err["Cause"].startswith(prefix) and err["Cause"].endswith("; Proxy: null)"), (
            f"{resource_name}'s Cause must name the missing ARN {missing_arn!r} in the "
            f"documented StateMachineDoesNotExist shape; got {err['Cause']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
