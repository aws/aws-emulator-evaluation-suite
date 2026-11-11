"""universal-target-sdk-service-id-vs-endpoint-prefix."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "universal-target-sdk-service-id-vs-endpoint-prefix"
GROUP = "error-semantics"
SERVICES = ["iam", "scheduler", "stepfunctions"]

_FIRE_OFFSET_S = 15
_EXECUTION_TIMEOUT_S = 180
_CREATE_TIMEOUT_S = 180
_SCHEDULER_ROLE_UNPROPAGATED = (
    "ValidationException", "The execution role you provide must allow AWS EventBridge Scheduler to assume the role.",
)
_SFN_ROLE_UNPROPAGATED = (
    "AccessDeniedException",
    "Neither the global service principal states.amazonaws.com, nor the regional one is "
    "authorized to assume the provided role.",
)

_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]

# A single Pass state: no downstream permissions are needed.
_DEFINITION = {
    "Comment": "sim2real fidelity probe: a target for a Scheduler universal target",
    "StartAt": "Echo",
    "States": {"Echo": {"Type": "Pass", "End": True}},
}

# The universal target's {{service}} segment must be the AWS SDK service identifier
# (stepfunctions' is "sfn"), not the API's HTTP endpoint prefix ("states").
_GOOD_ARN_SERVICE = "sfn"
_BAD_ARN_SERVICE = "states"


# timing:real-time — schedule: 15 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """A universal target's {{service}} segment is the AWS SDK service identifier, not the API's
    endpoint prefix: aws-sdk:states:startExecution is refused with ValidationException, leaving no
    schedule and no execution, while aws-sdk:sfn:startExecution is accepted and starts one.

    Reference: https://docs.aws.amazon.com/scheduler/latest/UserGuide/managing-targets-universal.html
    """
    sch = ctx.client("scheduler")
    sfn = ctx.client("stepfunctions")

    machine_arn = _create_state_machine(ctx)
    role_arn = _scheduler_role(
        ctx, [{"Effect": "Allow", "Action": "states:StartExecution", "Resource": machine_arn}]
    )

    good_arn = f"arn:aws:scheduler:::aws-sdk:{_GOOD_ARN_SERVICE}:startExecution"
    bad_arn = f"arn:aws:scheduler:::aws-sdk:{_BAD_ARN_SERVICE}:startExecution"

    exec_name = ctx.unique_name("accepted-")
    _create_schedule(
        ctx,
        ScheduleExpression=f"at({_future().strftime('%Y-%m-%dT%H:%M:%S')})",
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={
            "Arn": good_arn,
            "RoleArn": role_arn,
            "Input": json.dumps({"StateMachineArn": machine_arn, "Name": exec_name}),
        },
    )

    # (1) The positive control: the SDK-service-id spelling really starts an execution.
    execution = _poll_until(
        lambda: _find_execution(ctx, machine_arn, exec_name),
        lambda found: found is not None,
        timeout_s=_EXECUTION_TIMEOUT_S,
        interval_s=2.0,
        description=(
            f"Step Functions to record an execution named {exec_name} started by the universal "
            f"target {good_arn}"
        ),
    )
    described = _poll_until(
        lambda: sfn.describe_execution(executionArn=execution["executionArn"]),
        lambda d: d["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"),
        timeout_s=_EXECUTION_TIMEOUT_S,
        interval_s=1.0,
        description=f"execution {execution['executionArn']} to reach a terminal status",
    )
    assert described["status"] == "SUCCEEDED", (
        f"the execution started by {good_arn} ended {described['status']!r}, expected SUCCEEDED "
        f"for a single Pass state"
    )

    # (2) Break exactly one thing: the {{service}} segment becomes the endpoint prefix instead of
    # the SDK service id. No retry -- the barrier above already proved the role propagated, so any
    # refusal here is about the ARN.
    bad_name = ctx.unique_name("sim2real-behav-sched-badsvc-")
    bad_exec_name = ctx.unique_name("refused-")
    err = _error(
        lambda: sch.create_schedule(
            Name=bad_name,
            ScheduleExpression=f"at({_future().strftime('%Y-%m-%dT%H:%M:%S')})",
            ScheduleExpressionTimezone="UTC",
            FlexibleTimeWindow={"Mode": "OFF"},
            State="ENABLED",
            Target={
                "Arn": bad_arn,
                "RoleArn": role_arn,
                "Input": json.dumps({"StateMachineArn": machine_arn, "Name": bad_exec_name}),
            },
        )
    )
    code = err.get("Code")
    assert code == "ValidationException", (
        f"CreateSchedule accepted the universal target ARN {bad_arn!r}, whose service segment is "
        f"the endpoint prefix rather than the accepted SDK service id in {good_arn!r}, or refused "
        f"it with {code!r}"
    )
    expected_message = (
        f"Invalid RequestJson provided. Reason The api startExecution is not valid for the service "
        f"aws-sdk:{_BAD_ARN_SERVICE}."
    )
    assert err.get("Message") == expected_message, (
        f"expected CreateSchedule message {expected_message!r}, got {err.get('Message')!r}"
    )

    # (3) The effect is absent on the control plane: no schedule was created.
    get_err = _error(lambda: sch.get_schedule(Name=bad_name))
    assert get_err.get("Code") == "ResourceNotFoundException", (
        f"the refused CreateSchedule left the schedule {bad_name} behind ({get_err.get('Code')!r})"
    )
    expected_get_message = f"Schedule {bad_name} does not exist."
    assert get_err.get("Message") == expected_get_message, (
        f"expected GetSchedule message {expected_get_message!r}, got {get_err.get('Message')!r}"
    )

    # (4) And absent on the data plane: no execution was ever started for the refused spelling.
    never = _find_execution(ctx, machine_arn, bad_exec_name)
    assert never is None, (
        f"the refused universal target started an execution anyway: {never!r}"
    )


def _future():
    import datetime

    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0) + datetime.timedelta(
        seconds=_FIRE_OFFSET_S
    )


def _error(fn):
    """The botocore Error dict (Code, Message) a call raised. Raises if the call unexpectedly
    SUCCEEDS, so an emulator accepting input real AWS rejects can never read as a code mismatch."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError("the call was expected to fail but succeeded")


def _role(ctx, prefix: str, principal: str, statements: list[dict]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(prefix)
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": principal},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_MANAGED_TAGS_KV
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="sim2real-target",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
    return arn


def _scheduler_role(ctx, statements: list[dict]) -> str:
    return _role(ctx, "sim2real-behav-sched-role-", "scheduler.amazonaws.com", statements)


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    iam.delete_role(RoleName=role_name)


def _create_state_machine(ctx) -> str:
    """Create a STANDARD state machine; EXPRESS does not serve describe_execution."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sched-sm-")
    exec_role = _role(ctx, "sim2real-behav-sched-smrole-", "states.amazonaws.com", [])
    deadline = time.monotonic() + _CREATE_TIMEOUT_S
    last = None
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(_DEFINITION),
                roleArn=exec_role,
                type="STANDARD",
                tags=[{"key": "sim2real:managed", "value": "true"}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            last = exc
            # CreateStateMachine validates the execution role by assuming it, and IAM is eventually
            # consistent. The bounded retry is the wait.
            err = exc.response.get("Error", {})
            if (err.get("Code"), err.get("Message")) != _SFN_ROLE_UNPROPAGATED:
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"CreateStateMachine still refused after {_CREATE_TIMEOUT_S}s of IAM "
                    f"propagation: {last!r}"
                ) from last
            time.sleep(1)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _create_schedule(ctx, **kwargs) -> str:
    """Create a schedule, retrying the IAM-propagation refusal within a bound."""
    sch = ctx.client("scheduler")
    name = kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-sched-")
    deadline = time.monotonic() + _CREATE_TIMEOUT_S
    last = None
    while True:
        try:
            sch.create_schedule(Name=name, **kwargs)
            break
        except ClientError as exc:
            last = exc
            err = exc.response.get("Error", {})
            if (err.get("Code"), err.get("Message")) != _SCHEDULER_ROLE_UNPROPAGATED:
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"CreateSchedule still refused after {_CREATE_TIMEOUT_S}s of IAM "
                    f"propagation: {last!r}"
                ) from last
            time.sleep(1)
    ctx.on_cleanup(lambda: _delete_schedule(ctx, name))
    return name


def _delete_schedule(ctx, name: str) -> None:
    try:
        ctx.client("scheduler").delete_schedule(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _find_execution(ctx, machine_arn: str, name: str):
    """The execution named `name` on `machine_arn`, or None. ListExecutions names run by name."""
    sfn = ctx.client("stepfunctions")
    token = None
    while True:
        kwargs = {"stateMachineArn": machine_arn, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        page = sfn.list_executions(**kwargs)
        for item in page["executions"]:
            if item["name"] == name:
                return item
        token = page.get("nextToken")
        if not token:
            return None


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Poll until `predicate` holds; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"waited {timeout_s}s for {description}; last observation was {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
