"""execute-scheduled-report-dry-run-no-execution-triggered."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "execute-scheduled-report-dry-run-no-execution-triggered"
GROUP = "state"
SERVICES = ["bcm-dashboards"]


@tags("axis:negative-delivery", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ExecuteScheduledReport with dryRun=true validates configuration but never sets
    executionTriggered=true -- regardless of the report's health outcome."""
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

    resp = bcm.execute_scheduled_report(arn=arn, dryRun=True)
    assert not resp.get("executionTriggered"), resp

    got = bcm.get_scheduled_report(arn=arn)["scheduledReport"]
    assert "lastExecutionAt" not in got, got

    # Positive control: a real (non-dry-run) execution on the same wiring, moments
    # later, DOES trigger and DOES stamp lastExecutionAt. Without this, a target that
    # never actually executes anything -- dry run or not -- would pass the assertions
    # above for free.
    real_resp = bcm.execute_scheduled_report(arn=arn)
    assert real_resp.get("executionTriggered"), real_resp

    got_after_real = bcm.get_scheduled_report(arn=arn)["scheduledReport"]
    assert "lastExecutionAt" in got_after_real, got_after_real


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
