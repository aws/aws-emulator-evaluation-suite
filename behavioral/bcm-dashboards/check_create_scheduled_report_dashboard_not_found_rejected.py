"""create-scheduled-report-dashboard-not-found-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-scheduled-report-dashboard-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["bcm-dashboards"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateScheduledReport with a well-formed dashboardArn that does not exist fails at once with
    ValidationException "Dashboard not found: <arn>" and creates no report, while the same request
    against a real dashboard succeeds and stores that dashboardArn."""
    bcm = ctx.client("bcm-dashboards")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    nonexistent_dashboard_arn = (
        f"arn:aws:bcm-dashboards::{account_id}:dashboard/sim2real-never-existed-00000000"
    )
    role_arn = _create_execution_role(ctx)
    before = _list_all_scheduled_report_names(bcm)

    sr_name = ctx.unique_name("sim2real-sr-")
    code, message = _client_error_retrying(
        bcm,
        {
            "scheduledReport": {
                "name": sr_name,
                "dashboardArn": nonexistent_dashboard_arn,
                "scheduledReportExecutionRoleArn": role_arn,
                "scheduleConfig": {
                    "scheduleExpression": "cron(0 8 ? * MON *)",
                    "scheduleExpressionTimeZone": "UTC",
                },
            }
        },
    )
    assert code == "ValidationException", code
    assert message == f"Dashboard not found: {nonexistent_dashboard_arn}", message

    after = _list_all_scheduled_report_names(bcm)
    assert sr_name not in after and after == before, (sr_name, before, after)

    # positive control: the same shape, pointed at a real dashboard, succeeds
    dashboard_arn = _create_dashboard(ctx)
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
            },
            "resourceTags": [{"key": "sim2real", "value": CHECK}],
        },
    )["arn"]
    ctx.on_cleanup(lambda: bcm.delete_scheduled_report(arn=arn))
    actual_dashboard_arn = bcm.get_scheduled_report(arn=arn)["scheduledReport"]["dashboardArn"]
    assert actual_dashboard_arn == dashboard_arn, (dashboard_arn, actual_dashboard_arn)


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


def _client_error_retrying(bcm, spec: dict, *, timeout_s: float = 45, interval_s: float = 3):
    """Same retry semantics as _create_scheduled_report_retrying, but returns the (code,
    message) of the terminal (non-role-propagation) failure. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = _create_scheduled_report_retrying(
            bcm, spec, timeout_s=timeout_s, interval_s=interval_s
        )
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    bcm.delete_scheduled_report(arn=result["arn"])
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
    arn = bcm.create_dashboard(
        name=name,
        widgets=[_cost_widget("W1")],
        resourceTags=[{"key": "sim2real", "value": CHECK}],
    )["arn"]
    ctx.on_cleanup(lambda: bcm.delete_dashboard(arn=arn))
    return arn


def _list_all_scheduled_report_names(bcm) -> set[str]:
    out: set[str] = set()
    token = None
    while True:
        kwargs = {"nextToken": token} if token else {}
        resp = bcm.list_scheduled_reports(maxResults=100, **kwargs)
        out.update(r["name"] for r in resp["scheduledReports"])
        token = resp.get("nextToken")
        if not token:
            break
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

