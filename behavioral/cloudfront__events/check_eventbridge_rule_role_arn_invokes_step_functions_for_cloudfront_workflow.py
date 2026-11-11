"""eventbridge-rule-role-arn-invokes-step-functions-for-cloudfront-workflow."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-rule-role-arn-invokes-step-functions-for-cloudfront-workflow"
GROUP = "orchestration"
SERVICES = ["cloudfront", "events"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFront-shaped event matched by an EventBridge rule starts its Step Functions target
    through the target's trusted RoleArn, and the execution carries the event detail to SUCCEEDED.
    """
    iam = ctx.client("iam")
    events = ctx.client("events")
    sfn = ctx.client("stepfunctions")

    sfn_role_name = ctx.unique_name("sim2real-cfsfn-smrole-")
    sfn_trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    check_tag = [{"Key": "sim2real-check", "Value": CHECK}]
    sfn_role_arn = iam.create_role(
        RoleName=sfn_role_name, AssumeRolePolicyDocument=json.dumps(sfn_trust), Tags=check_tag,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=sfn_role_name))

    definition = {
        "Comment": "sim2real cloudfront workflow echo",
        "StartAt": "Echo",
        "States": {"Echo": {"Type": "Pass", "End": True}},
    }
    sm_name = ctx.unique_name("sim2real-cfsfn-sm-")
    sm_arn = _create_state_machine_with_retry(
        sfn, sm_name, definition, sfn_role_arn, tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    events_role_name = ctx.unique_name("sim2real-cfsfn-eventsrole-")
    events_trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    events_role_arn = iam.create_role(
        RoleName=events_role_name, AssumeRolePolicyDocument=json.dumps(events_trust), Tags=check_tag,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=events_role_name))
    start_exec_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "states:StartExecution", "Resource": sm_arn}],
    }
    iam.put_role_policy(RoleName=events_role_name, PolicyName="start-execution", PolicyDocument=json.dumps(start_exec_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=events_role_name, PolicyName="start-execution"))

    rule_name = ctx.unique_name("sim2real-cfsfn-rule-")
    pattern = {
        "source": ["sim2real.cloudfront"],
        "detail-type": ["CloudFront Distribution Event (Simulated)"],
        "detail": {"eventName": ["CreateInvalidation"]},
    }
    events.put_rule(Name=rule_name, EventPattern=json.dumps(pattern), Tags=check_tag)
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    target_id = "sfn-target"
    events.put_targets(
        Rule=rule_name,
        Targets=[{"Id": target_id, "Arn": sm_arn, "RoleArn": events_role_arn}],
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=[target_id]))

    # Real CloudFront events arrive via CloudTrail (up to ~15 min), so a synthetic
    # CreateInvalidation-shaped event is injected with PutEvents instead.
    def _send() -> str:
        marker = ctx.unique_name("marker-")
        events.put_events(Entries=[{
            "Source": "sim2real.cloudfront",
            "DetailType": "CloudFront Distribution Event (Simulated)",
            "Detail": json.dumps({"eventName": "CreateInvalidation", "distributionId": "E1EXAMPLE12345", "marker": marker}),
        }])
        return marker

    # IAM role trust/policy propagation into EventBridge's target-invocation path
    # can lag tens of seconds after create_role/put_role_policy return, and a
    # single AssumeRole failure there is NOT retried by EventBridge itself — so
    # resend a fresh event (new marker) until one gets through.
    execution_arn, marker = _send_until_delivered(
        _send, lambda m: _wait_for_execution_with_marker(sfn, sm_arn, m, timeout_s=20),
    )
    assert execution_arn is not None, "expected EventBridge to start a Step Functions execution via the trusted role"
    status = _wait_for_terminal_status(sfn, execution_arn, timeout_s=60)
    assert status == "SUCCEEDED", f"expected execution {execution_arn} to reach SUCCEEDED, got {status}"

    desc = sfn.describe_execution(executionArn=execution_arn)
    exec_input = json.loads(desc["input"])
    assert exec_input["source"] == "sim2real.cloudfront", (
        f"expected execution input source 'sim2real.cloudfront', got {exec_input.get('source')!r}"
    )
    assert exec_input["detail"]["distributionId"] == "E1EXAMPLE12345", (
        f"expected distributionId 'E1EXAMPLE12345' in execution input, got {exec_input['detail'].get('distributionId')!r}"
    )
    assert exec_input["detail"]["marker"] == marker, (
        f"expected execution input marker {marker!r}, got {exec_input['detail'].get('marker')!r}"
    )



def _create_state_machine_with_retry(
    sfn: Any, name: str, definition: dict, role_arn: str, tags: list | None = None, timeout_s: float = 60.0,
) -> str:
    """IAM role trust can take a few seconds to propagate; retry the transient failure."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD",
                tags=tags or [],
            )["stateMachineArn"]
        except ClientError as exc:
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never succeeded within {timeout_s}s: {last_err}")


def _send_until_delivered(send_fn: Any, poll_fn: Any, overall_timeout_s: float = 180.0, retry_gap_s: float = 5.0):
    deadline = time.monotonic() + overall_timeout_s
    last_marker = None
    while time.monotonic() < deadline:
        last_marker = send_fn()
        result = poll_fn(last_marker)
        if result is not None:
            return result, last_marker
        time.sleep(retry_gap_s)
    return None, last_marker



def _wait_for_execution_with_marker(sfn: Any, sm_arn: str, marker: str, timeout_s: float = 120.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for execution in sfn.list_executions(stateMachineArn=sm_arn)["executions"]:
            desc = sfn.describe_execution(executionArn=execution["executionArn"])
            try:
                exec_input = json.loads(desc["input"])
            except (ValueError, KeyError):
                continue
            if exec_input.get("detail", {}).get("marker") == marker:
                return execution["executionArn"]
        time.sleep(3)
    return None


def _wait_for_terminal_status(sfn: Any, execution_arn: str, timeout_s: float = 60.0) -> str:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = sfn.describe_execution(executionArn=execution_arn)["status"]
        if status != "RUNNING":
            return status
        time.sleep(2)
    raise AssertionError(f"execution {execution_arn} never left RUNNING within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
