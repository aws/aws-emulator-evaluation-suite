"""confused-deputy-source-arn-mismatch-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "confused-deputy-source-arn-mismatch-denied"
GROUP = "confused_deputy"
SERVICES = ["iam", "stepfunctions"]

# A Task that calls out through the execution role, so the role is actually assumed: a
# Pass-only execution never needs the role at all and would "succeed" under any trust.
_DEFINITION = json.dumps({
    "StartAt": "WhoAmI",
    "States": {
        "WhoAmI": {
            "Type": "Task",
            "Resource": "arn:aws:states:::aws-sdk:sts:getCallerIdentity",
            "Parameters": {},
            "End": True,
        },
    },
})


def _trust(condition: dict) -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": condition,
        }],
    })


def _create_role(ctx, condition: dict) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-cdmis-")[:64]
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_trust(condition), Path="/sim2real/",
        Description="sim2real-xsvc: sfn confused-deputy mismatch trust role",
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name, PolicyName="whoami",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "sts:GetCallerIdentity", "Resource": "*"}]}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="whoami"))
    return arn


def _create_named_state_machine(ctx, name: str, role_arn: str,
                                *, deadline_s: float = 120.0) -> str:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + deadline_s
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=_DEFINITION, roleArn=role_arn, type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK[:250]}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(4.0)
            continue
        ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
        return arn
    raise AssertionError(f"CreateStateMachine {name!r} still AccessDenied after {deadline_s}s: {last}")


_TRUST_RACE_MARKERS = ("not authorized to assume the provided role",)


def _run_once(ctx, sm_arn: str) -> dict:
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-xsvc-cdmis-exec-"), input="{}",
    )["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, exec_arn))
    return _wait_terminal(ctx, exec_arn)


def _run_control_past_propagation(ctx, sm_arn: str, *, deadline_s: float = 150.0) -> dict:
    """Run the matching-trust control to terminal, retrying only the IAM-trust propagation
    race (never a genuine denial, which this role's trust should never produce)."""
    deadline = time.monotonic() + deadline_s
    desc = None
    while time.monotonic() < deadline:
        desc = _run_once(ctx, sm_arn)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _TRUST_RACE_MARKERS):
            return desc
        time.sleep(4.0)
    raise AssertionError(f"control execution of {sm_arn!r} never got past trust propagation: {desc!r}")


def _wait_terminal(ctx, exec_arn: str, *, timeout_s: float = 60.0) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(2.0)
    raise AssertionError(f"execution {exec_arn} still RUNNING after {timeout_s}s: {last!r}")


def _best_effort_stop(ctx, exec_arn: str) -> None:
    sfn = ctx.client("stepfunctions")
    try:
        if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
            sfn.stop_execution(executionArn=exec_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """An execution role whose trust requires aws:SourceArn equal to a state machine ARN that
    is never this one's own is not assumable: a Task that calls through the role FAILS on
    every attempt, while a twin role trusting this machine's real ARN succeeds.
    """
    region, account = ctx.region, ctx.account

    good_name = ctx.unique_name("sim2real-xsvc-cdmis-good-")
    good_arn = f"arn:aws:states:{region}:{account}:stateMachine:{good_name}"
    good_role = _create_role(ctx, {"ArnEquals": {"aws:SourceArn": good_arn}})
    good_sm = _create_named_state_machine(ctx, good_name, good_role)
    assert good_sm == good_arn, f"created ARN {good_sm!r} != predicted {good_arn!r}"

    bad_name = ctx.unique_name("sim2real-xsvc-cdmis-bad-")
    bad_arn = f"arn:aws:states:{region}:{account}:stateMachine:{bad_name}"
    other_arn = (f"arn:aws:states:{region}:{account}:stateMachine:"
                 f"{ctx.unique_name('sim2real-xsvc-cdmis-other-')}")
    bad_role = _create_role(ctx, {"ArnEquals": {"aws:SourceArn": other_arn}})
    bad_sm = _create_named_state_machine(ctx, bad_name, bad_role)
    assert bad_sm == bad_arn, f"created ARN {bad_sm!r} != predicted {bad_arn!r}"

    good = _run_control_past_propagation(ctx, good_sm)
    assert good["status"] == "SUCCEEDED", (
        f"control: a trust whose SourceArn equals this machine's own ARN must SUCCEED; got "
        f"{good['status']!r} error={good.get('error')!r} cause={good.get('cause')!r}")

    want_cause = (
        "The principal states.amazonaws.com is not authorized to assume the provided role. "
        f"(role: {bad_role})")
    for _ in range(3):
        bad = _run_once(ctx, bad_sm)
        assert bad["status"] == "FAILED" and bad["error"] == "States.TaskFailed", (
            f"a trust whose SourceArn can never equal this machine's own ARN must FAIL every "
            f"attempt with States.TaskFailed; got {bad['status']!r} error={bad.get('error')!r}")
        assert bad["cause"] == want_cause, (
            f"the cause must name exactly the un-assumable role; got {bad['cause']!r}, "
            f"expected {want_cause!r}")

    listed = ctx.client("stepfunctions").list_executions(stateMachineArn=bad_sm)["executions"]
    assert all(e["status"] == "FAILED" for e in listed), (
        f"every execution of the mismatched-trust machine must end FAILED; got "
        f"{[(e['name'], e['status']) for e in listed]}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
