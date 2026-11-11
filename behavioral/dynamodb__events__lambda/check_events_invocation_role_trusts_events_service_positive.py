"""events-invocation-role-trusts-events-service-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-invocation-role-trusts-events-service-positive"
GROUP = "iam-trust"
SERVICES = ["dynamodb", "events", "lambda"]

_SM_DEFINITION = {
    "Comment": "sim2real role-trust probe",
    "StartAt": "Pass",
    "States": {"Pass": {"Type": "Pass", "End": True}},
}


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule whose Step Functions target uses a role trusting events.amazonaws.com starts an execution that
    SUCCEEDS with the event's marker as input: EventBridge assumed the role to call states:StartExecution.
    """
    sfn = ctx.client("stepfunctions")
    events = ctx.client("events")
    iam = ctx.client("iam")

    sm_arn = _create_state_machine(ctx, sfn, iam)
    ir_arn = _create_invocation_role(ctx, iam, "events.amazonaws.com", sm_arn)

    rule_name = ctx.unique_name("sim2real-evt-trust-ok-rule-")
    pattern = {"source": ["sim2real.roletrust"], "detail-type": ["role-trust-positive"]}
    events.put_rule(Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED")
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    _put_targets_with_retry(
        events,
        Rule=rule_name,
        Targets=[{"Id": "1", "Arn": sm_arn, "RoleArn": ir_arn}],
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["1"]))

    marker = ctx.unique_name("marker-")

    def _emit():
        events.put_events(
            Entries=[
                {
                    "Source": "sim2real.roletrust",
                    "DetailType": "role-trust-positive",
                    "Detail": json.dumps({"marker": marker}),
                }
            ]
        )

    _emit()

    execution = _poll_until_with_retry_emit(
        lambda: _list_executions(sfn, sm_arn),
        lambda execs: len(execs) >= 1,
        emit=_emit,
        timeout_s=180.0,
        interval_s=5.0,
        emit_every_s=30.0,
    )[0]

    desc = _poll_until(
        lambda: sfn.describe_execution(executionArn=execution["executionArn"]),
        lambda d: d["status"] != "RUNNING",
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert desc["status"] == "SUCCEEDED", desc
    input_doc = json.loads(desc["input"])
    assert input_doc["detail"]["marker"] == marker, input_doc


def _trust_policy(principal_service: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": principal_service},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )


def _create_role(ctx, iam, role_name: str, principal_service: str) -> str:
    resp = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_trust_policy(principal_service)
    )
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
    sm_name = ctx.unique_name("sim2real-roletrust-sm-")

    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(
                name=sm_name,
                definition=json.dumps(_SM_DEFINITION),
                roleArn=sm_role_arn,
                type="STANDARD",
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
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "states:StartExecution", "Resource": sm_arn}
                ],
            }
        ),
    )
    return role_arn


def _put_targets_with_retry(
    events, *, timeout_s: float = 60.0, interval_s: float = 3.0, **kwargs: Any
):
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
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


def _poll_until_with_retry_emit(
    probe,
    predicate,
    *,
    emit,
    timeout_s: float = 180.0,
    interval_s: float = 5.0,
    emit_every_s: float = 30.0,
):
    """Like _poll_until, but periodically re-fires `emit()` in case the first
    EventBridge invocation attempt landed before IAM trust propagation completed
    and the automatic retry window has not yet re-attempted the target."""
    deadline = time.monotonic() + timeout_s
    next_emit = time.monotonic() + emit_every_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= next_emit:
            emit()
            next_emit = time.monotonic() + emit_every_s
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
