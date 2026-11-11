"""iam-role-trusts-events-service-for-target-invocation."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from behavioral_harness import tags

CHECK = "iam-role-trusts-events-service-for-target-invocation"
GROUP = "permission-boundary"
SERVICES = ["backup", "events"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role whose trust policy allows events.amazonaws.com lets EventBridge invoke a Step
    Functions target when a Backup-shaped event on a custom source matches, observed as an
    execution that reaches SUCCEEDED."""
    events = ctx.client("events")
    sfn = ctx.client("stepfunctions")

    machine_arn = _create_pass_state_machine(ctx)

    rule_name = ctx.unique_name("sim2real-rule-")
    source = f"sim2real.test.{rule_name}"
    pattern = {
        "source": [source],
        "detail-type": ["Backup Job State Change"],
        "detail": {"state": ["COMPLETED"]},
    }
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    invoke_role_arn = _create_events_invoke_role(ctx, machine_arn, rule_arn)
    _put_target_with_retry(events, rule_name, machine_arn, invoke_role_arn)
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["t1"]))

    execution_arn = _fire_until_invoked(events, sfn, source, machine_arn)
    final_status = _poll_until(
        lambda: sfn.describe_execution(executionArn=execution_arn)["status"],
        lambda s: s in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"),
        timeout_s=60.0,
        interval_s=3.0,
        description=f"execution {execution_arn} terminal status",
    )
    assert final_status == "SUCCEEDED", f"execution ended in {final_status}, expected SUCCEEDED"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _fire_until_invoked(events, sfn, source: str, machine_arn: str, timeout_s: float = 220.0) -> str:
    """Re-fire a fresh event (new marker) every attempt rather than waiting on EventBridge's own
    invocation-retry backoff, which is far slower than this check's budget: a role that was not yet
    assumable for the first attempt is normally assumable well within a couple of these attempts."""
    deadline = time.monotonic() + timeout_s
    last_marker = None
    while time.monotonic() < deadline:
        marker = str(uuid.uuid4())
        last_marker = marker
        events.put_events(
            Entries=[
                {
                    "Source": source,
                    "DetailType": "Backup Job State Change",
                    "Detail": json.dumps({"backupJobId": marker, "state": "COMPLETED"}),
                }
            ]
        )
        attempt_deadline = time.monotonic() + 20.0
        while time.monotonic() < attempt_deadline:
            execution_arn = _find_execution(sfn, machine_arn, marker)
            if execution_arn is not None:
                return execution_arn
            time.sleep(4.0)
    raise AssertionError(
        f"no state machine execution started for any fired marker within {timeout_s}s (last marker {last_marker})"
    )


def _create_pass_state_machine(ctx) -> str:
    iam = ctx.client("iam")
    sfn = ctx.client("stepfunctions")

    role_name = ctx.unique_name("sim2real-sfnrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    definition = json.dumps(
        {"Comment": "sim2real minimal pass machine", "StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}}
    )
    machine_name = ctx.unique_name("sim2real-sfn-")

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 60.0
    last_exc: Exception | None = None
    machine_arn = None
    while time.monotonic() < deadline:
        try:
            machine_arn = sfn.create_state_machine(
                name=machine_name,
                definition=definition,
                roleArn=role_arn,
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidDefinition" or "assumable" in str(exc).lower() or exc.response["Error"]["Code"] == "AccessDeniedException":
                last_exc = exc
                time.sleep(3.0)
                continue
            raise
    if machine_arn is None:
        raise AssertionError(f"CreateStateMachine never succeeded within 60s: {last_exc}")
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=machine_arn))
    return machine_arn


def _create_events_invoke_role(ctx, machine_arn: str, rule_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-evtrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="start-execution",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "states:StartExecution", "Resource": machine_arn}]}
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="start-execution"))
    return role_arn


def _put_target_with_retry(events, rule_name: str, machine_arn: str, role_arn: str, timeout_s: float = 60.0) -> None:
    """IAM is eventually consistent: retry until EventBridge accepts (and can later assume)
    the freshly created invoke role rather than sleeping a fixed duration."""
    deadline = time.monotonic() + timeout_s
    last_failure: Any = None
    while time.monotonic() < deadline:
        resp = events.put_targets(
            Rule=rule_name, Targets=[{"Id": "t1", "Arn": machine_arn, "RoleArn": role_arn}]
        )
        if resp.get("FailedEntryCount", 0) == 0:
            return
        last_failure = resp.get("FailedEntries")
        time.sleep(3.0)
    raise AssertionError(f"PutTargets never succeeded within {timeout_s}s: {last_failure}")


def _find_execution(sfn, machine_arn: str, marker: str) -> str | None:
    paginator = sfn.get_paginator("list_executions")
    for page in paginator.paginate(stateMachineArn=machine_arn):
        for execution in page.get("executions", []):
            exec_arn = execution["executionArn"]
            try:
                history = sfn.get_execution_history(executionArn=exec_arn, maxResults=5)
            except Exception:
                continue
            for evt in history.get("events", []):
                details = evt.get("executionStartedEventDetails", {})
                if marker in details.get("input", ""):
                    return exec_arn
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
