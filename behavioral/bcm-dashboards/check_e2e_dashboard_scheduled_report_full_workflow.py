"""e2e-dashboard-scheduled-report-full-workflow."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-dashboard-scheduled-report-full-workflow"
GROUP = "e2e"
SERVICES = ["bcm-dashboards"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tagged dashboard and a scheduled report on it keep their tags, the report is HEALTHY on a dry run
    before and after the dashboard's widgets are replaced and its schedule goes DISABLED then ENABLED,
    and after deletion both fail ResourceNotFoundException with their exact not-found messages."""
    bcm = ctx.client("bcm-dashboards")

    # 1. create a tagged dashboard with one widget
    dash_name = ctx.unique_name("sim2real-dash-")
    dashboard_arn = bcm.create_dashboard(
        name=dash_name,
        widgets=[_cost_widget("Initial Widget")],
        resourceTags=[{"key": "workflow", "value": "e2e"}],
    )["arn"]
    dashboard_deleted = False
    ctx.on_cleanup(lambda: None if dashboard_deleted else bcm.delete_dashboard(arn=dashboard_arn))

    dashboard_tags = {
        t["key"]: t["value"] for t in bcm.list_tags_for_resource(resourceArn=dashboard_arn)["resourceTags"]
    }
    assert dashboard_tags.get("workflow") == "e2e", f"expected dashboard tag workflow=e2e, got {dashboard_tags!r}"

    # 2. create an execution role and a scheduled report pointed at the dashboard
    role_arn = _create_execution_role(ctx)
    sr_name = ctx.unique_name("sim2real-sr-")
    report_arn = _create_scheduled_report_retrying(
        bcm,
        {
            "scheduledReport": {
                "name": sr_name,
                "dashboardArn": dashboard_arn,
                "scheduledReportExecutionRoleArn": role_arn,
                "scheduleConfig": {
                    "scheduleExpression": "cron(0 8 ? * MON *)",
                    "scheduleExpressionTimeZone": "UTC",
                    "state": "ENABLED",
                },
            }
        },
    )["arn"]
    report_deleted = False
    ctx.on_cleanup(lambda: None if report_deleted else bcm.delete_scheduled_report(arn=report_arn))

    got = bcm.get_scheduled_report(arn=report_arn)["scheduledReport"]
    assert got["dashboardArn"] == dashboard_arn, (
        f"expected dashboardArn {dashboard_arn!r}, got {got['dashboardArn']!r}"
    )
    assert got["scheduledReportExecutionRoleArn"] == role_arn, (
        f"expected scheduledReportExecutionRoleArn {role_arn!r}, "
        f"got {got['scheduledReportExecutionRoleArn']!r}"
    )

    # 3. confirm it starts HEALTHY (role is assumable, dashboard exists)
    dry_run_resp = bcm.execute_scheduled_report(arn=report_arn, dryRun=True)
    assert dry_run_resp["healthStatus"]["statusCode"] == "HEALTHY", (
        f"expected healthStatus.statusCode HEALTHY, got {dry_run_resp['healthStatus']!r}"
    )
    assert not dry_run_resp.get("executionTriggered"), (
        f"expected no execution triggered on dry run, got {dry_run_resp.get('executionTriggered')!r}"
    )

    # 4. tag the scheduled report independently of the dashboard's tags
    bcm.tag_resource(resourceArn=report_arn, resourceTags=[{"key": "workflow", "value": "e2e-report"}])
    report_tags = {
        t["key"]: t["value"] for t in bcm.list_tags_for_resource(resourceArn=report_arn)["resourceTags"]
    }
    assert report_tags.get("workflow") == "e2e-report", (
        f"expected report tag workflow=e2e-report, got {report_tags!r}"
    )

    # 5. disable then re-enable the schedule, verifying each transition
    bcm.update_scheduled_report(arn=report_arn, scheduleConfig={"state": "DISABLED"})
    state = bcm.get_scheduled_report(arn=report_arn)["scheduledReport"]["scheduleConfig"]["state"]
    assert state == "DISABLED", f"expected state DISABLED after update, got {state!r}"
    bcm.update_scheduled_report(arn=report_arn, scheduleConfig={"state": "ENABLED"})
    state = bcm.get_scheduled_report(arn=report_arn)["scheduledReport"]["scheduleConfig"]["state"]
    assert state == "ENABLED", f"expected state ENABLED after re-enable, got {state!r}"

    # 6. replace the dashboard's widgets entirely, then confirm the change
    bcm.update_dashboard(arn=dashboard_arn, name=dash_name, widgets=[_cost_widget("Replaced Widget")])
    updated_dashboard = bcm.get_dashboard(arn=dashboard_arn)
    titles = {w["title"] for w in updated_dashboard["widgets"]}
    assert titles == {"Replaced Widget"}, f"expected widget titles {{'Replaced Widget'}}, got {titles!r}"

    # 7. the scheduled report is still HEALTHY against the (now-updated) dashboard
    dry_run_resp = bcm.execute_scheduled_report(arn=report_arn, dryRun=True)
    assert dry_run_resp["healthStatus"]["statusCode"] == "HEALTHY", (
        f"expected healthStatus.statusCode HEALTHY after widget replacement, "
        f"got {dry_run_resp['healthStatus']!r}"
    )

    # 8. tear down in dependency order: scheduled report first, then dashboard
    bcm.delete_scheduled_report(arn=report_arn)
    report_deleted = True
    code, message = _client_error(lambda: bcm.get_scheduled_report(arn=report_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after deleting the report, got {code!r}"
    )
    assert message == f"Scheduled report not found: {report_arn}", message

    bcm.delete_dashboard(arn=dashboard_arn)
    dashboard_deleted = True
    code, message = _client_error(lambda: bcm.get_dashboard(arn=dashboard_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after deleting the dashboard, got {code!r}"
    )
    assert message == f"Resource {dashboard_arn} does not exist.", message


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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "workflow", "Value": "e2e"}],
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


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). An unexpected success raises, so
    accepting what AWS refuses fails as itself and not as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

