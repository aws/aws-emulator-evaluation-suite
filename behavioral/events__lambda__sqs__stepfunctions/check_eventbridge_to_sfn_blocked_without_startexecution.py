"""eventbridge-to-sfn-blocked-without-startexecution."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-to-sfn-blocked-without-startexecution"

GROUP = "overly-permissive"

SERVICES = ["events", "lambda", "stepfunctions", "sqs"]

_PASS_DEFINITION = {
    "StartAt": "Done",
    "States": {"Done": {"Type": "Pass", "End": True}},
}


def _put_rule(ctx, pattern, name_hint="rule"):
    events = ctx.client("events")
    rule_name = ctx.unique_name(name_hint)
    resp = events.put_rule(
        Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED"
    )
    ctx.on_cleanup(lambda: ctx.client("events").delete_rule(Name=rule_name))
    return rule_name, resp["RuleArn"]


def _assert_stays_empty(ctx, probe, settle_s, what):
    """Assert *probe* never returns a truthy value within the settle window."""
    deadline = time.monotonic() + settle_s
    while True:
        observed = probe()
        assert not observed, f"{what}: expected no effect, observed {observed!r}"
        if time.monotonic() >= deadline:
            return
        time.sleep(5)


@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A target whose role lacks states:StartExecution starts no execution, while a permitted
    twin target on the same rule, fired by the same PutEvents call, starts one."""
    sfn_role = _create_role_stmts(ctx, "states.amazonaws.com", [], "sfn-role")
    sm_ctl_arn = _create_state_machine_role(ctx, _PASS_DEFINITION, sfn_role, "sm-ctl")
    sm_arn = _create_state_machine_role(ctx, _PASS_DEFINITION, sfn_role, "sm-blocked")

    eb_role_ctl = _create_role_stmts(
        ctx,
        "events.amazonaws.com",
        [{"Effect": "Allow", "Action": "states:StartExecution", "Resource": sm_ctl_arn}],
        "eb-role-ctl",
    )
    eb_role = _create_role_stmts(ctx, "events.amazonaws.com", [], "eb-role-noperm")

    rule_name, _rule_arn = _put_rule(
        ctx, {"source": ["sim2real.xsvc.sfnnoperm"]}, "rule-sfn-noperm"
    )
    events = ctx.client("events")
    resp = events.put_targets(
        Rule=rule_name,
        Targets=[
            {"Id": "sm-ctl", "Arn": sm_ctl_arn, "RoleArn": eb_role_ctl},
            {"Id": "sm-noperm", "Arn": sm_arn, "RoleArn": eb_role},
        ],
    )
    ctx.on_cleanup(
        lambda: ctx.client("events").remove_targets(
            Rule=rule_name, Ids=["sm-ctl", "sm-noperm"]
        )
    )
    assert resp["FailedEntryCount"] == 0, f"control plane rejected the targets: {resp}"

    # The events roles were just created and service-principal trust propagation has no
    # pollable signal; EventBridge drops an invocation that cannot assume the role. Re-fire
    # the event until the permitted twin starts, bounded, instead of a blind pre-send sleep.
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 150
    ctl_execs = []
    while not ctl_execs:
        pe = events.put_events(
            Entries=[
                {
                    "Source": "sim2real.xsvc.sfnnoperm",
                    "DetailType": "Start",
                    "Detail": "{}",
                }
            ]
        )
        assert pe["FailedEntryCount"] == 0, pe
        attempt_deadline = min(deadline, time.monotonic() + 30)
        while True:
            ctl_execs = sfn.list_executions(stateMachineArn=sm_ctl_arn)["executions"]
            if ctl_execs or time.monotonic() >= attempt_deadline:
                break
            time.sleep(5)
        if not ctl_execs and time.monotonic() >= deadline:
            break
    assert ctl_execs, (
        "positive-control twin never started -- the rule/target wiring is not "
        "demonstrably live, so the unpermitted twin's absence would prove nothing"
    )

    noperm_execs = sfn.list_executions(stateMachineArn=sm_arn)["executions"]
    assert not noperm_execs, (
        f"EventBridge started a Step Functions execution without states:StartExecution: {noperm_execs!r}"
    )

    _assert_stays_empty(
        ctx,
        lambda: sfn.list_executions(stateMachineArn=sm_arn)["executions"],
        30,
        "EventBridge started a Step Functions execution without states:StartExecution",
    )


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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
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
    return role["Role"]["Arn"]


def _create_state_machine_role(ctx, definition, role_arn, name_hint="sm"):
    """Create a state machine, tolerating IAM propagation delay."""
    sfn = ctx.client("stepfunctions")
    sm_name = ctx.unique_name(name_hint)

    def probe():
        try:
            return sfn.create_state_machine(
                name=sm_name, definition=json.dumps(definition), roleArn=role_arn
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
