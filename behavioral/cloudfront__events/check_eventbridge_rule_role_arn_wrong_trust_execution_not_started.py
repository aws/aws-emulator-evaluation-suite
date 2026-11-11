"""eventbridge-rule-role-arn-wrong-trust-execution-not-started."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-rule-role-arn-wrong-trust-execution-not-started"
GROUP = "permission-boundary"
SERVICES = ["cloudfront", "events"]


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "cap:c7",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A matching event starts no Step Functions execution while the target RoleArn trusts only
    lambda.amazonaws.com; re-pointed at a role trusting events.amazonaws.com, the same rule starts
    an execution that reaches SUCCEEDED."""
    iam = ctx.client("iam")
    events = ctx.client("events")
    sfn = ctx.client("stepfunctions")

    check_tag = [{"Key": "sim2real-check", "Value": CHECK}]

    sfn_role_name = ctx.unique_name("sim2real-cfwrong-smrole-")
    sfn_trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    sfn_role_arn = iam.create_role(
        RoleName=sfn_role_name, AssumeRolePolicyDocument=json.dumps(sfn_trust), Tags=check_tag,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=sfn_role_name))

    definition = {
        "Comment": "sim2real cloudfront workflow echo (wrong-trust check)",
        "StartAt": "Echo",
        "States": {"Echo": {"Type": "Pass", "End": True}},
    }
    sm_name = ctx.unique_name("sim2real-cfwrong-sm-")
    sm_arn = _create_state_machine_with_retry(
        sfn, sm_name, definition, sfn_role_arn, tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    start_exec_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "states:StartExecution", "Resource": sm_arn}],
    }

    bad_role_name = ctx.unique_name("sim2real-cfwrong-badrole-")
    bad_trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    bad_role_arn = iam.create_role(
        RoleName=bad_role_name, AssumeRolePolicyDocument=json.dumps(bad_trust), Tags=check_tag,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=bad_role_name))
    iam.put_role_policy(RoleName=bad_role_name, PolicyName="start-execution", PolicyDocument=json.dumps(start_exec_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=bad_role_name, PolicyName="start-execution"))

    rule_name = ctx.unique_name("sim2real-cfwrong-rule-")
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
        Targets=[{"Id": target_id, "Arn": sm_arn, "RoleArn": bad_role_arn}],
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=[target_id]))

    marker_bad = ctx.unique_name("marker-bad-")
    events.put_events(Entries=[{
        "Source": "sim2real.cloudfront",
        "DetailType": "CloudFront Distribution Event (Simulated)",
        "Detail": json.dumps({"eventName": "CreateInvalidation", "distributionId": "E1EXAMPLE12345", "marker": marker_bad}),
    }])

    # bounded absence check: the untrusted role must never let an execution start
    found = _wait_for_execution_with_marker(sfn, sm_arn, marker_bad, timeout_s=75)
    assert found is None, "execution must not start when the target RoleArn's trust policy omits events.amazonaws.com"

    # positive control: same rule, same state machine, a correctly-trusted role
    good_role_name = ctx.unique_name("sim2real-cfwrong-goodrole-")
    good_trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    good_role_arn = iam.create_role(
        RoleName=good_role_name, AssumeRolePolicyDocument=json.dumps(good_trust), Tags=check_tag,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=good_role_name))
    iam.put_role_policy(RoleName=good_role_name, PolicyName="start-execution", PolicyDocument=json.dumps(start_exec_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=good_role_name, PolicyName="start-execution"))

    events.put_targets(
        Rule=rule_name,
        Targets=[{"Id": target_id, "Arn": sm_arn, "RoleArn": good_role_arn}],
    )
    def _send_good() -> str:
        m = ctx.unique_name("marker-good-")
        events.put_events(Entries=[{
            "Source": "sim2real.cloudfront",
            "DetailType": "CloudFront Distribution Event (Simulated)",
            "Detail": json.dumps({"eventName": "CreateInvalidation", "distributionId": "E1EXAMPLE12345", "marker": m}),
        }])
        return m

    # IAM role trust/policy propagation into EventBridge's target-invocation path
    # can lag tens of seconds after create_role/put_role_policy return, and a
    # single AssumeRole failure there is NOT retried by EventBridge itself — so
    # resend a fresh event (new marker) until one gets through.
    execution_arn, marker_good = _send_until_delivered(
        _send_good, lambda m: _wait_for_execution_with_marker(sfn, sm_arn, m, timeout_s=20),
    )
    assert execution_arn is not None, "positive control with a correctly-trusted role must start an execution"
    status = _wait_for_terminal_status(sfn, execution_arn, timeout_s=60)
    assert status == "SUCCEEDED", f"expected execution {execution_arn} to reach SUCCEEDED, got {status}"


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
