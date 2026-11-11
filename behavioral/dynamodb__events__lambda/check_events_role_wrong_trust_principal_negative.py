"""events-role-wrong-trust-principal-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "events-role-wrong-trust-principal-negative"
GROUP = "overly-permissive"
SERVICES = ["dynamodb", "events", "lambda"]

_SM_DEFINITION = {
    "Comment": "sim2real wrong-trust probe",
    "StartAt": "Pass",
    "States": {"Pass": {"Type": "Pass", "End": True}},
}


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule whose target role trusts s3.amazonaws.com, not events.amazonaws.com, starts no execution, while
    the same rule shape with a correctly trusted role starts one that SUCCEEDS: the state machine holds exactly
    one execution.
    """
    sfn = ctx.client("stepfunctions")
    events = ctx.client("events")
    iam = ctx.client("iam")

    sm_arn = _create_state_machine(ctx, sfn, iam)

    wrong_role_arn = _create_invocation_role(ctx, iam, "s3.amazonaws.com", sm_arn)
    good_role_arn = _create_invocation_role(ctx, iam, "events.amazonaws.com", sm_arn)

    wrong_rule = ctx.unique_name("sim2real-evt-wrong-trust-rule-")
    good_rule = ctx.unique_name("sim2real-evt-good-trust-rule-")

    events.put_rule(
        Name=wrong_rule,
        EventPattern=json.dumps({"source": ["sim2real.wrongtrust"], "detail-type": ["wrong-trust"]}),
        State="ENABLED",
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=wrong_rule))
    events.put_rule(
        Name=good_rule,
        EventPattern=json.dumps({"source": ["sim2real.wrongtrust"], "detail-type": ["good-trust"]}),
        State="ENABLED",
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=good_rule))

    _put_targets_with_retry(
        events, Rule=wrong_rule, Targets=[{"Id": "1", "Arn": sm_arn, "RoleArn": wrong_role_arn}]
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=wrong_rule, Ids=["1"]))
    _put_targets_with_retry(
        events, Rule=good_rule, Targets=[{"Id": "1", "Arn": sm_arn, "RoleArn": good_role_arn}]
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=good_rule, Ids=["1"]))

    # events.amazonaws.com can never assume a role whose trust names s3.amazonaws.com, so one
    # emit is enough: no wait or retry would make it succeed.
    events.put_events(
        Entries=[{"Source": "sim2real.wrongtrust", "DetailType": "wrong-trust", "Detail": json.dumps({})}]
    )

    def _emit_good() -> None:
        events.put_events(
            Entries=[{"Source": "sim2real.wrongtrust", "DetailType": "good-trust", "Detail": json.dumps({})}]
        )

    # Positive control: the correctly trusted role's rule produces an execution. A new role's
    # trust can take tens of seconds to reach EventBridge and an event matched before then is
    # not retried, so each bounded attempt re-emits until one execution appears.
    good_execution = _poll_with_retry_emit(
        lambda: _list_executions(sfn, sm_arn),
        lambda execs: len(execs) >= 1,
        emit=_emit_good,
        total_timeout_s=195.0,
        attempt_timeout_s=15.0,
        interval_s=5.0,
    )[0]
    desc = _poll_until(
        lambda: sfn.describe_execution(executionArn=good_execution["executionArn"]),
        lambda d: d["status"] != "RUNNING",
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert desc["status"] == "SUCCEEDED", desc

    # the wrongly-trusted role never got EventBridge an execution: exactly one
    # execution total exists on this otherwise-fresh state machine.
    executions = _list_executions(sfn, sm_arn)
    assert len(executions) == 1, executions


def _trust_policy(principal_service: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": principal_service}, "Action": "sts:AssumeRole"}
            ],
        }
    )


def _create_role(ctx, iam, role_name: str, principal_service: str) -> str:
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_trust_policy(principal_service))
    role_arn = resp["Role"]["Arn"]

    def _cleanup():
        try:
            for pol in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_state_machine(ctx, sfn, iam, timeout_s: float = 60.0, interval_s: float = 3.0) -> str:
    sm_role_name = ctx.unique_name("sim2real-sfn-exec-role-")
    sm_role_arn = _create_role(ctx, iam, sm_role_name, "states.amazonaws.com")
    sm_name = ctx.unique_name("sim2real-wrongtrust-sm-")

    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(
                name=sm_name, definition=json.dumps(_SM_DEFINITION), roleArn=sm_role_arn, type="STANDARD"
            )
            sm_arn = resp["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))
            return sm_arn
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "InvalidDefinition"):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    assert last_exc is not None
    raise last_exc


def _create_invocation_role(ctx, iam, principal_service: str, sm_arn: str) -> str:
    role_name = ctx.unique_name("sim2real-evt-invoke-role-")
    role_arn = _create_role(ctx, iam, role_name, principal_service)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="start-execution",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "states:StartExecution", "Resource": sm_arn}]}
        ),
    )
    return role_arn


def _put_targets_with_retry(events, *, timeout_s: float = 60.0, interval_s: float = 3.0, **kwargs: Any):
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        resp = events.put_targets(**kwargs)
        if resp.get("FailedEntryCount", 0) == 0:
            return resp
        last_exc = AssertionError(str(resp.get("FailedEntries")))
        time.sleep(interval_s)
    raise last_exc if last_exc else AssertionError("put_targets never succeeded")


def _list_executions(sfn, sm_arn: str) -> list[dict[str, Any]]:
    return sfn.list_executions(stateMachineArn=sm_arn).get("executions", [])


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _poll_with_retry_emit(
    probe,
    predicate,
    *,
    emit,
    total_timeout_s: float,
    attempt_timeout_s: float,
    interval_s: float,
):
    """Re-fires `emit()` at the start of each bounded attempt until `predicate`
    holds. Safe against a duplicate success: an attempt whose own window closes
    without `predicate` holding is treated as dead, never revisited."""
    deadline = time.monotonic() + total_timeout_s
    last = None
    while time.monotonic() < deadline:
        emit()
        attempt_deadline = min(deadline, time.monotonic() + attempt_timeout_s)
        while time.monotonic() < attempt_deadline:
            last = probe()
            if predicate(last):
                return last
            time.sleep(interval_s)
    raise AssertionError(f"condition not met within {total_timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
