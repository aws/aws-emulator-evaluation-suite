"""execute-scheduled-report-role-not-assumable-unhealthy."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "execute-scheduled-report-role-not-assumable-unhealthy"
GROUP = "state"
SERVICES = ["bcm-dashboards"]


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ExecuteScheduledReport's dry-run health is HEALTHY right after creation, turns UNHEALTHY with
    reason EXECUTION_ROLE_ASSUME_FAILED once the role's trust policy drops the bcm-dashboards
    principal, and returns to HEALTHY when the trust is restored."""
    bcm = ctx.client("bcm-dashboards")
    iam = ctx.client("iam")
    dashboard_arn = _create_dashboard(ctx)
    role_name, role_arn = _create_execution_role(ctx)

    sr_name = ctx.unique_name("sim2real-sr-")
    arn = _create_scheduled_report_retrying(
        bcm,
        {
            "scheduledReport": {
                "name": sr_name,
                "dashboardArn": dashboard_arn,
                "scheduledReportExecutionRoleArn": role_arn,
                "scheduleConfig": {
                    "scheduleExpression": "cron(0 8 ? * MON *)",
                    "scheduleExpressionTimeZone": "UTC",
                },
            }
        },
    )["arn"]
    ctx.on_cleanup(lambda: bcm.delete_scheduled_report(arn=arn))

    # positive control: right after creation, the role is assumable and health is HEALTHY
    resp = bcm.execute_scheduled_report(arn=arn, dryRun=True)
    assert resp["healthStatus"]["statusCode"] == "HEALTHY", resp["healthStatus"]

    # break assumability: the role trusts only EC2, not bcm-dashboards
    broken_trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.update_assume_role_policy(
        RoleName=role_name, PolicyDocument=json.dumps(broken_trust_policy)
    )

    def _now_unhealthy():
        r = bcm.execute_scheduled_report(arn=arn, dryRun=True)
        h = r["healthStatus"]
        return h if h["statusCode"] == "UNHEALTHY" else None

    health = _poll_until_truthy(_now_unhealthy, timeout_s=45, interval_s=3)
    assert health is not None, "health status never became UNHEALTHY after breaking role trust"
    assert "EXECUTION_ROLE_ASSUME_FAILED" in health.get("statusReasons", []), health

    # restore: trust bcm-dashboards again, and the identical dry-run call now reports HEALTHY
    restored_trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bcm-dashboards.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.update_assume_role_policy(
        RoleName=role_name, PolicyDocument=json.dumps(restored_trust_policy)
    )

    def _now_healthy():
        r = bcm.execute_scheduled_report(arn=arn, dryRun=True)
        h = r["healthStatus"]
        return h if h["statusCode"] == "HEALTHY" else None

    restored_health = _poll_until_truthy(_now_healthy, timeout_s=45, interval_s=3)
    assert restored_health is not None, "health status never returned to HEALTHY after restoring role trust"


def _poll_until_truthy(fn, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        result = fn()
        if result:
            return result
        time.sleep(interval_s)
    return fn()


def _create_scheduled_report_retrying(bcm, spec: dict, *, timeout_s: float = 45, interval_s: float = 3):
    """CreateScheduledReport synchronously validates that it can assume the execution
    role; a just-created IAM role can take a few seconds to propagate, so retry on that
    specific transient failure rather than treating it as a hard error."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return bcm.create_scheduled_report(**spec)
        except ClientError as err:
            msg = (err.response.get("Error", {}).get("Message") or "")
            if "assume" in msg.lower() and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _cost_widget(title: str) -> dict:
    return {
        "title": title,
        "configs": [
            {
                "queryParameters": {
                    "costAndUsage": {
                        "metrics": ["UnblendedCost"],
                        "timeRange": {
                            "startTime": {"type": "RELATIVE", "value": "-P1M"},
                            "endTime": {"type": "RELATIVE", "value": "-P0D"},
                        },
                        "granularity": "MONTHLY",
                    }
                },
                "displayConfig": {"table": {}},
            }
        ],
    }


def _create_dashboard(ctx) -> str:
    bcm = ctx.client("bcm-dashboards")
    name = ctx.unique_name("sim2real-dash-")
    arn = bcm.create_dashboard(name=name, widgets=[_cost_widget("W1")])["arn"]
    ctx.on_cleanup(lambda: bcm.delete_dashboard(arn=arn))
    return arn


def _create_execution_role(ctx) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-bcmdash-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bcm-dashboards.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
    )

    def _cleanup():
        try:
            iam.detach_role_policy(
                RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_name, role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

