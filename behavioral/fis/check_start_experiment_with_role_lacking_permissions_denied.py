"""start-experiment-with-role-lacking-permissions-denied."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-experiment-with-role-lacking-permissions-denied"
GROUP = "overly-permissive"
SERVICES = ["fis"]

_TERMINAL_STATUSES = {"completed", "stopped", "failed", "cancelled"}


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:fis-active-experiment-quota")
def run(ctx) -> None:
    """An experiment whose role lacks the action's permission ends failed rather than completed,
    while an identical template with a properly permissioned role completes."""
    cw = ctx.client("cloudwatch")
    fis = ctx.client("fis")

    alarm_name = ctx.unique_name("sim2real-fis-perm-alarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace="Sim2RealFIS",
        MetricName="DummyPermissionCheckMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))
    alarm_arn = _wait_for_alarm_state(cw, alarm_name, "INSUFFICIENT_DATA", timeout_s=30.0)

    role_denied = _create_fis_role(ctx)
    role_allowed = _create_fis_role(
        ctx,
        policy_statements=[{"Effect": "Allow", "Action": "cloudwatch:DescribeAlarms", "Resource": "*"}],
    )

    template_denied = _create_assert_alarm_template(ctx, fis, role_denied, alarm_arn)
    experiment_denied = _start_experiment_with_retry(fis, ctx, template_denied)
    eid_denied = experiment_denied["id"]
    ctx.on_cleanup(lambda: _best_effort_stop(fis, eid_denied))

    status_denied = _poll_experiment_status(fis, eid_denied, _TERMINAL_STATUSES, timeout_s=120.0)
    assert status_denied == "failed", (
        f"expected the experiment to fail when its role lacks cloudwatch:DescribeAlarms, "
        f"got status={status_denied!r}"
    )
    detail_denied = fis.get_experiment(id=eid_denied)["experiment"]
    assert detail_denied["state"]["status"] == "failed", (
        f"expected get_experiment to independently confirm status=failed, "
        f"got status={detail_denied['state']['status']!r}"
    )
    reason_denied = detail_denied["state"].get("reason", "")
    assert "not enough privileges" in reason_denied.lower(), (
        f"expected the recorded failure reason to name an insufficient-privileges "
        f"failure (not some other execution error), got reason={reason_denied!r}"
    )

    # Positive control: identical template/action, but the role has the permission.
    template_allowed = _create_assert_alarm_template(ctx, fis, role_allowed, alarm_arn)
    experiment_allowed = fis.start_experiment(
        clientToken=ctx.unique_name("sim2real-fis-tok-"),
        experimentTemplateId=template_allowed,
    )["experiment"]
    eid_allowed = experiment_allowed["id"]
    ctx.on_cleanup(lambda: _best_effort_stop(fis, eid_allowed))

    status_allowed = _poll_experiment_status(fis, eid_allowed, _TERMINAL_STATUSES, timeout_s=120.0)
    assert status_allowed == "completed", (
        f"expected the permissioned-role experiment to complete, got status={status_allowed!r}"
    )


# ===== helpers =====

def _create_fis_role(ctx, policy_statements: list[dict[str, Any]] | None = None) -> str:
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
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    if policy_statements:
        policy_name = ctx.unique_name("sim2real-fis-policy-")
        iam.put_role_policy(
            RoleName=name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": policy_statements}),
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


def _create_assert_alarm_template(ctx, fis, role_arn: str, alarm_arn: str) -> str:
    template = _create_experiment_template(
        ctx,
        fis,
        clientToken=ctx.unique_name("sim2real-fis-tok-"),
        description="sim2real fis role-permission execution check",
        stopConditions=[{"source": "none"}],
        actions={
            "assert1": {
                "actionId": "aws:cloudwatch:assert-alarm-state",
                "parameters": {"alarmArns": alarm_arn, "alarmStates": "INSUFFICIENT_DATA"},
            }
        },
        targets={},
        roleArn=role_arn,
        tags={"sim2real-check": CHECK},
    )
    template_id = template["id"]
    ctx.on_cleanup(lambda: fis.delete_experiment_template(id=template_id))
    return template_id


def _wait_for_alarm_state(cw, alarm_name: str, expected_state: str, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        alarm = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
        last_state = alarm["StateValue"]
        if last_state == expected_state:
            return alarm["AlarmArn"]
        time.sleep(2.0)
    raise AssertionError(f"alarm {alarm_name} never reached state {expected_state!r}, last={last_state!r}")


def _poll_experiment_status(fis, experiment_id: str, target_statuses: set, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"]
        if last in target_statuses:
            return last
        time.sleep(3.0)
    raise AssertionError(f"experiment {experiment_id} never reached {target_statuses}, last status={last!r}")


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
