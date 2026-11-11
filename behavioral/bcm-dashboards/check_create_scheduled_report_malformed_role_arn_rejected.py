"""create-scheduled-report-malformed-role-arn-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-scheduled-report-malformed-role-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["bcm-dashboards"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateScheduledReport with a role ARN whose account id has 3 digits fails with ValidationException
    and the exact pattern message and creates no report; a well-formed role ARN succeeds, and after its
    delete GetScheduledReport fails with ResourceNotFoundException "Scheduled report not found: <arn>"."""
    bcm = ctx.client("bcm-dashboards")
    dashboard_arn = _create_dashboard(ctx)
    before = _list_all_scheduled_report_names(bcm)

    sr_name = ctx.unique_name("sim2real-sr-")
    malformed_role_arn = "arn:aws:iam::123:role/not-a-real-account-id"
    code, message = _client_error(
        lambda: bcm.create_scheduled_report(
            scheduledReport={
                "name": sr_name,
                "dashboardArn": dashboard_arn,
                "scheduledReportExecutionRoleArn": malformed_role_arn,
                "scheduleConfig": {
                    "scheduleExpression": "cron(0 8 ? * MON *)",
                    "scheduleExpressionTimeZone": "UTC",
                },
            }
        )
    )
    assert code == "ValidationException", code
    expected_message = (
        "1 validation error detected: Value '" + malformed_role_arn + "' at "
        "'scheduledReport.scheduledReportExecutionRoleArn' failed to satisfy constraint: Member "
        "must satisfy regular expression pattern: "
        "arn:aws[-a-z0-9]*:iam::[0-9]{12}:role/[a-zA-Z0-9+=,.@_/-]+"
    )
    assert message == expected_message, message

    after = _list_all_scheduled_report_names(bcm)
    assert sr_name not in after and after == before, (before, after)

    # positive control: a real, well-formed role ARN succeeds
    role_arn = _create_execution_role(ctx)
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
    deleted = False
    ctx.on_cleanup(lambda: None if deleted else bcm.delete_scheduled_report(arn=arn))
    got = bcm.get_scheduled_report(arn=arn)["scheduledReport"]
    assert got["name"] == sr_name, got

    # the cleanup delete is a free negative: prove the report is gone and unusable afterward
    bcm.delete_scheduled_report(arn=arn)
    deleted = True
    code, message = _client_error(lambda: bcm.get_scheduled_report(arn=arn))
    assert code == "ResourceNotFoundException", code
    assert message == f"Scheduled report not found: {arn}", message


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
