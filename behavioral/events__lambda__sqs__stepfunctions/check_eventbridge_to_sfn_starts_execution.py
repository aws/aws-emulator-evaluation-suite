"""eventbridge-to-sfn-starts-execution."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-to-sfn-starts-execution"

GROUP = "event-propagation"

SERVICES = ["events", "lambda", "stepfunctions", "sqs"]

_PASS_DEFINITION = {
    "StartAt": "Done",
    "States": {"Done": {"Type": "Pass", "End": True}},
}


_TAG_KV = [{"Key": "sim2real:managed", "Value": "true"}]


def _put_rule(ctx, pattern, name_hint="rule"):
    events = ctx.client("events")
    rule_name = ctx.unique_name(name_hint)
    resp = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=_TAG_KV,
    )
    ctx.on_cleanup(lambda: ctx.client("events").delete_rule(Name=rule_name))
    return rule_name, resp["RuleArn"]


def _put_events_until(ctx, entries, probe, timeout_s=75, interval_s=6):
    """PutEvents repeatedly until a downstream effect appears.

    Rule/target creation on the default bus is eventually consistent: an event
    published immediately after PutTargets can be silently dropped. Republishing
    while polling makes the positive path deterministic.
    """
    events = ctx.client("events")

    def attempt():
        resp = events.put_events(Entries=entries)
        assert resp["FailedEntryCount"] == 0, resp
        return probe()

    return _poll_until(
        attempt, lambda r: bool(r), timeout_s=timeout_s, interval_s=interval_s
    )


def _wait_execution_settled(ctx, exec_arn, timeout_s=60):
    sfn = ctx.client("stepfunctions")
    return _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"),
        timeout_s=timeout_s,
        interval_s=2,
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """EventBridge target with states:StartExecution starts an execution carrying the EB envelope."""
    sfn = ctx.client("stepfunctions")
    events = ctx.client("events")

    sfn_role = _create_role_stmts(ctx, "states.amazonaws.com", [], "sfn-role")
    sm_arn = _create_state_machine_role(ctx, _PASS_DEFINITION, sfn_role, "sm")
    eb_role = _create_role_stmts(
        ctx,
        "events.amazonaws.com",
        [{"Effect": "Allow", "Action": "states:StartExecution", "Resource": sm_arn}],
        "eb-role",
    )

    rule_name, _rule_arn = _put_rule(ctx, {"source": ["sim2real.xsvc.sfn"]}, "rule-sfn")
    events.put_targets(
        Rule=rule_name,
        Targets=[{"Id": "sfn-target", "Arn": sm_arn, "RoleArn": eb_role}],
    )
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(Rule=rule_name, Ids=["sfn-target"])
    )

    execs = _put_events_until(
        ctx,
        [
            {
                "Source": "sim2real.xsvc.sfn",
                "DetailType": "Start",
                "Detail": json.dumps({"job": "j-1"}),
            }
        ],
        lambda: sfn.list_executions(stateMachineArn=sm_arn)["executions"],
        timeout_s=70,
    )
    desc = _wait_execution_settled(ctx, execs[0]["executionArn"], timeout_s=30)
    assert desc["status"] == "SUCCEEDED", desc

    input_data = json.loads(desc["input"])
    assert input_data["source"] == "sim2real.xsvc.sfn", input_data
    assert input_data["detail-type"] == "Start", input_data
    assert input_data["detail"]["job"] == "j-1", input_data


def _create_role_stmts(ctx, service_principal, statements, name_hint="role"):
    """Create a role trusting *service_principal* with an optional inline policy."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name(name_hint)
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": service_principal},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=_TAG_KV,
    )
    ctx.on_cleanup(lambda: ctx.client("iam").delete_role(RoleName=role_name))
    if statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps(
                {"Version": "2012-10-17", "Statement": statements}
            ),
        )
        ctx.on_cleanup(
            lambda: ctx.client("iam").delete_role_policy(
                RoleName=role_name, PolicyName="inline"
            )
        )
    # Service-principal trust propagation has no pollable signal, so there is nothing to
    # bound-retry here. The wait happens at the consumers instead: create_state_machine's
    # retry-past-ClientError loop below, and _put_events_until's republish loop for the
    # EventBridge target role, both already bounded with a deadline.
    return role["Role"]["Arn"]


def _create_state_machine_role(ctx, definition, role_arn, name_hint="sm"):
    """Create a state machine, tolerating IAM propagation delay."""
    sfn = ctx.client("stepfunctions")
    sm_name = ctx.unique_name(name_hint)

    def probe():
        try:
            return sfn.create_state_machine(
                name=sm_name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                tags=[{"key": "sim2real:managed", "value": "true"}],
            )
        except ClientError:
            return None

    sm = _wait_for_effect(probe, lambda r: r is not None, timeout_s=90)
    ctx.on_cleanup(
        lambda: ctx.client("stepfunctions").delete_state_machine(
            stateMachineArn=sm["stateMachineArn"]
        )
    )
    return sm["stateMachineArn"]


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _wait_for_effect(
    probe, predicate, timeout_s=120.0, interval_s=2.0, description="effect"
):
    """Poll for an async cross-service effect (default 120s — Kinesis/DDB-stream ESMs can need
    60-120s for cold-start + first delivery; fast effects return as soon as the predicate holds)."""
    return _poll_until(
        probe,
        predicate,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=description,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
