"""execute-scheduled-report-health-status-populated-after-dry-run."""
from __future__ import annotations

import datetime as dt
import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "execute-scheduled-report-health-status-populated-after-dry-run"
GROUP = "state"
SERVICES = ["bcm-dashboards"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ExecuteScheduledReport evaluates and returns a real healthStatus (HEALTHY, since
    the dashboard exists and the execution role is assumable, with a lastRefreshedAt
    freshly computed by this call) even for a dry run."""
    bcm = ctx.client("bcm-dashboards")
    dashboard_arn = _create_dashboard(ctx)
    role_arn = _create_execution_role(ctx)

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

    # The service clock and the runner clock differ, and the stamp may be whole seconds, so the
    # lower bound allows a few seconds of skew.
    before = dt.datetime.now(dt.timezone.utc).replace(microsecond=0) - dt.timedelta(seconds=5)
    resp = bcm.execute_scheduled_report(arn=arn, dryRun=True)
    health = resp["healthStatus"]
    assert health["statusCode"] == "HEALTHY", health
    assert "lastRefreshedAt" in health, health
    assert health["lastRefreshedAt"] >= before, (health["lastRefreshedAt"], before)

    # the evaluated health status is also surfaced back through GetScheduledReport
    got = bcm.get_scheduled_report(arn=arn)["scheduledReport"]
    assert got["healthStatus"]["statusCode"] == "HEALTHY", got["healthStatus"]


def _create_scheduled_report_retrying(bcm, spec: dict, *, timeout_s: float = 45, interval_s: float = 3):
    """CreateScheduledReport synchronously validates that it can assume the execution
    role; a just-created IAM role can take a few seconds to propagate, so retry on that
    specific transient failure rather than treating it as a hard error."""
    import time
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


def _create_execution_role(ctx, assume_service: str = "bcm-dashboards.amazonaws.com") -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-bcmdash-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": assume_service}, "Action": "sts:AssumeRole"}
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
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
