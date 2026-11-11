"""eventbridge-target-role-wrong-trust-blocks-sfn-start."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-target-role-wrong-trust-blocks-sfn-start"
GROUP = "permission-boundary"
SERVICES = ["events", "lambda", "s3", "stepfunctions"]


@tags("axis:negative-delivery", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EventBridge target IAM role trusted by lambda.amazonaws.com instead of
    events.amazonaws.com cannot be assumed by the rule, so StartExecution is never called;
    fixing the trust policy (positive control) then lets the execution start."""
    sfn_role_arn = _create_role(ctx, "states.amazonaws.com")
    sm_arn = _create_state_machine(
        ctx, sfn_role_arn, {"StartAt": "Echo", "States": {"Echo": {"Type": "Pass", "End": True}}}
    )

    event_source = ctx.unique_name("sim2real.wrongtrust.")
    rule_name, rule_arn = _put_rule(ctx, {"source": [event_source]})

    start_execution_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "states:StartExecution", "Resource": sm_arn}],
    }
    wrong_trust_role_arn = _create_role(
        ctx, "lambda.amazonaws.com", inline_policy=start_execution_policy
    )
    _retry_until(
        lambda: _put_targets(
            ctx, rule_name, [{"Id": "sfn-target", "Arn": sm_arn, "RoleArn": wrong_trust_role_arn}]
        ),
        retryable_codes=("ValidationException",),
    )

    events = ctx.client("events")
    events.put_events(
        Entries=[{"Source": event_source, "DetailType": "WrongTrustTest", "Detail": json.dumps({"n": 1})}]
    )

    # --- negative: the target role cannot be assumed by events.amazonaws.com ---
    executions = _wait_executions(ctx, sm_arn, min_count=1, timeout_s=45)
    assert not executions, "an execution started despite the target role's trust policy excluding events.amazonaws.com"

    # --- positive control: a correctly-trusted role for the same target then unblocks it ---
    correct_role_arn = _create_role(ctx, "events.amazonaws.com", inline_policy=start_execution_policy)
    _retry_until(
        lambda: _put_targets(
            ctx, rule_name, [{"Id": "sfn-target", "Arn": sm_arn, "RoleArn": correct_role_arn}]
        ),
        retryable_codes=("ValidationException",),
    )

    def fire_correct():
        events.put_events(
            Entries=[{"Source": event_source, "DetailType": "WrongTrustTest", "Detail": json.dumps({"n": 2})}]
        )

    fire_correct()
    # EventBridge does not retry an AccessDeniedException from a just-created target role that
    # hasn't finished propagating, so re-fire the same event until the role has propagated.
    executions2 = _fire_until(
        fire_correct, lambda: _wait_executions(ctx, sm_arn, min_count=1, timeout_s=10), timeout_s=120, interval_s=10
    )
    assert executions2, "correcting the target role's trust policy never resulted in a started execution"
    execution = _wait_for_terminal(ctx, executions2[0]["executionArn"], timeout_s=60)
    assert execution["status"] == "SUCCEEDED", (
        f"expected the execution started via the corrected target role to reach SUCCEEDED, "
        f"got {execution['status']}"
    )


def _create_role(
    ctx,
    principal: str,
    inline_policy: dict[str, Any] | None = None,
    managed_arns: list[str] | None = None,
) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    for arn in managed_arns or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
    if inline_policy:
        iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy))
    return role["Arn"]


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
        for name in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
            iam.delete_role_policy(RoleName=role_name, PolicyName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _retry_until(fn, retryable_codes: tuple[str, ...], timeout_s: float = 90.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in retryable_codes:
                last_err = e
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"operation never succeeded after retrying for role propagation: {last_err}")


def _create_state_machine(ctx, role_arn: str, definition: dict[str, Any]) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-sm-")
    resp = _retry_until(
        lambda: sfn.create_state_machine(
            name=name,
            definition=json.dumps(definition),
            roleArn=role_arn,
            type="STANDARD",
            tags=[{"key": "sim2real", "value": CHECK}],
        ),
        retryable_codes=("AccessDeniedException",),
    )
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _put_rule(ctx, pattern: dict[str, Any]) -> tuple[str, str]:
    events = ctx.client("events")
    name = ctx.unique_name("sim2real-rule-")
    resp = events.put_rule(
        Name=name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=name, Force=True))
    return name, resp["RuleArn"]


def _put_targets(ctx, rule_name: str, targets: list[dict[str, Any]]) -> None:
    events = ctx.client("events")
    resp = events.put_targets(Rule=rule_name, Targets=targets)
    if resp.get("FailedEntryCount", 0):
        raise AssertionError(f"put_targets failed: {resp}")


def _fire_until(fire_fn, poll_fn, timeout_s: float = 120.0, interval_s: float = 10.0):
    """Repeatedly re-fires and polls because EventBridge does not retry an AccessDeniedException
    from a just-created target IAM role that hasn't finished propagating; a fresh event must be
    delivered after propagation completes."""
    deadline = time.monotonic() + timeout_s
    result = poll_fn()
    while not result and time.monotonic() < deadline:
        fire_fn()
        time.sleep(interval_s)
        result = poll_fn()
    return result


def _wait_executions(ctx, sm_arn: str, min_count: int = 1, timeout_s: float = 90.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        execs = sfn.list_executions(stateMachineArn=sm_arn).get("executions", [])
        if len(execs) >= min_count:
            return execs
        time.sleep(3)
    return sfn.list_executions(stateMachineArn=sm_arn).get("executions", [])



def _wait_for_terminal(ctx, execution_arn: str, timeout_s: float = 90.0) -> dict[str, Any]:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sfn.describe_execution(executionArn=execution_arn)
        if resp["status"] != "RUNNING":
            return resp
        time.sleep(3)
    raise AssertionError("execution did not reach a terminal state in time")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
