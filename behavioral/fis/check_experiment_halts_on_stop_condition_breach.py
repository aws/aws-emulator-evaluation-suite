"""experiment-halts-on-stop-condition-breach."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "experiment-halts-on-stop-condition-breach"
GROUP = "server-side"
SERVICES = ["fis"]

_TERMINAL_OR_RUNNING = {"running", "completed", "stopped", "failed", "cancelled"}
_TERMINAL = {"completed", "stopped", "failed", "cancelled"}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "resource:account-singleton:fis-active-experiment-quota")
def run(ctx) -> None:
    """A running experiment whose template declares a CloudWatch-alarm stop condition
    is transitioned to stopped by the service itself when the alarm goes into ALARM,
    with no StopExperiment call ever made by the caller."""
    cw = ctx.client("cloudwatch")
    fis = ctx.client("fis")

    alarm_name = ctx.unique_name("sim2real-fis-stopcond-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace="Sim2RealFIS",
        MetricName="DummyStopConditionMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))
    alarm_arn = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["AlarmArn"]
    # FIS rejects a stop-condition alarm that is not in the OK state at experiment
    # start time; force it to OK first (it starts as INSUFFICIENT_DATA).
    cw.set_alarm_state(
        AlarmName=alarm_name,
        StateValue="OK",
        StateReason="sim2real fis stop-condition breach test setup",
    )

    role_arn = _create_fis_role(ctx)
    template_id = _create_stop_condition_template(ctx, fis, role_arn, alarm_arn)

    experiment = _start_experiment_with_retry(fis, ctx, template_id)
    eid = experiment["id"]
    ctx.on_cleanup(lambda: _best_effort_stop(fis, eid))

    status_before_breach = _poll_experiment_status(fis, eid, _TERMINAL_OR_RUNNING, timeout_s=180.0)
    if status_before_breach != "running":
        reason = fis.get_experiment(id=eid)["experiment"]["state"].get("reason")
        raise AssertionError(
            f"experiment did not reach running before the alarm was triggered, "
            f"last status={status_before_breach!r} reason={reason!r}"
        )

    cw.set_alarm_state(
        AlarmName=alarm_name,
        StateValue="ALARM",
        StateReason="sim2real fis stop-condition breach test trigger",
    )

    final_status = _poll_experiment_status(fis, eid, _TERMINAL, timeout_s=180.0)
    assert final_status == "stopped", (
        f"expected the service to auto-stop the experiment on the alarm breach "
        f"without an explicit StopExperiment call, got status={final_status!r}"
    )


# ===== helpers =====

def _create_fis_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-fis-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "fis.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    # FIS evaluates alarm-based stop conditions using the experiment role, so it
    # needs permission to describe the alarm.
    policy_name = ctx.unique_name("sim2real-fis-policy-")
    iam.put_role_policy(
        RoleName=name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "cloudwatch:DescribeAlarms", "Resource": "*"}],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName=policy_name))
    return role_arn


def _create_experiment_template(ctx, fis, **kwargs) -> dict[str, Any]:
    deadline = time.monotonic() + 45.0
    while True:
        try:
            return fis.create_experiment_template(**kwargs)["experimentTemplate"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException" and time.monotonic() < deadline:
                time.sleep(3.0)
                continue
            raise


def _create_stop_condition_template(ctx, fis, role_arn: str, alarm_arn: str) -> str:
    template = _create_experiment_template(
        ctx,
        fis,
        clientToken=ctx.unique_name("sim2real-fis-tok-"),
        description="sim2real fis stop-condition server-side enforcement check",
        stopConditions=[{"source": "aws:cloudwatch:alarm", "value": alarm_arn}],
        actions={"wait1": {"actionId": "aws:fis:wait", "parameters": {"duration": "PT10M"}}},
        targets={},
        roleArn=role_arn,
        tags={"sim2real-check": CHECK},
    )
    template_id = template["id"]
    ctx.on_cleanup(lambda: fis.delete_experiment_template(id=template_id))
    return template_id


def _poll_experiment_status(fis, experiment_id: str, target_statuses: set, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    reason = None
    while time.monotonic() < deadline:
        state = fis.get_experiment(id=experiment_id)["experiment"]["state"]
        last = state["status"]
        reason = state.get("reason")
        if last in target_statuses:
            return last
        time.sleep(3.0)
    raise AssertionError(
        f"experiment {experiment_id} never reached {target_statuses}, last status={last!r} reason={reason!r}"
    )


def _best_effort_stop(fis, experiment_id: str) -> None:
    try:
        fis.stop_experiment(id=experiment_id)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        # an experiment already in a final state rejects StopExperiment; it needs no stop
        status = fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"]
        if status not in ("stopping", "stopped", "completed", "failed", "cancelled"):
            raise


def _start_experiment_with_retry(fis, ctx, template_id: str, deadline_s: float = 45.0) -> dict[str, Any]:
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return fis.start_experiment(
                clientToken=ctx.unique_name("sim2real-fis-tok-"),
                experimentTemplateId=template_id,
            )["experiment"]
        except ClientError as exc:
            err = exc.response["Error"]
            if (
                err["Code"] == "ValidationException"
                and "unable to assume role" in err.get("Message", "").lower()
                and time.monotonic() < deadline
            ):
                time.sleep(3.0)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

