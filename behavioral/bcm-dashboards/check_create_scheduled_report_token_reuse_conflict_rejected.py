"""create-scheduled-report-token-reuse-conflict-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-scheduled-report-token-reuse-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["bcm-dashboards"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Reusing a clientToken that already created a scheduled report fails with ConflictException and the
    exact message, with a different name or the same parameters, and creates no second report; a fresh
    token creates a distinct report, and the original stays listed under its name."""
    bcm = ctx.client("bcm-dashboards")
    dashboard_arn = _create_dashboard(ctx)
    role_arn = _create_execution_role(ctx)

    token = ctx.unique_name("sim2real-token-")
    original_name = ctx.unique_name("sim2real-sr-")
    base_request = {
        "dashboardArn": dashboard_arn,
        "scheduledReportExecutionRoleArn": role_arn,
        "scheduleConfig": {
            "scheduleExpression": "cron(0 8 ? * MON *)",
            "scheduleExpressionTimeZone": "UTC",
        },
    }

    original_arn = _create_scheduled_report_retrying(
        bcm,
        {
            "scheduledReport": {"name": original_name, **base_request},
            "clientToken": token,
            "resourceTags": [{"key": "env", "value": "sim2real-behavioral"}],
        },
    )["arn"]
    ctx.on_cleanup(lambda: bcm.delete_scheduled_report(arn=original_arn))

    conflict_message = (
        f"A scheduled report with the provided clientToken already exists (ARN: {original_arn}). "
        "Use a different clientToken to create a new scheduled report, or use the existing "
        "report's ARN to update it."
    )
    different_name = ctx.unique_name("sim2real-sr-conflict-")
    code, message = _client_error(
        lambda: bcm.create_scheduled_report(
            scheduledReport={"name": different_name, **base_request}, clientToken=token
        ),
        on_unexpected_success=lambda result: ctx.on_cleanup(
            lambda: bcm.delete_scheduled_report(arn=result["arn"])
        ),
    )
    assert code == "ConflictException", code
    assert message == conflict_message, message

    by_name = _list_scheduled_reports_by_name(bcm)
    assert different_name not in by_name, "a second report was created under a different name"

    # reusing the SAME token with the SAME parameters is ALSO rejected -- the token is
    # single-use, not a mirrored idempotent-retry mechanism
    code, message = _client_error(
        lambda: bcm.create_scheduled_report(
            scheduledReport={"name": original_name, **base_request}, clientToken=token
        ),
        on_unexpected_success=lambda result: ctx.on_cleanup(
            lambda: bcm.delete_scheduled_report(arn=result["arn"])
        ),
    )
    assert code == "ConflictException", code
    assert message == conflict_message, message

    # positive control: a fresh, never-used token succeeds and creates a distinct report
    fresh_token = ctx.unique_name("sim2real-token-")
    fresh_name = ctx.unique_name("sim2real-sr-fresh-")
    fresh_arn = _create_scheduled_report_retrying(
        bcm,
        {
            "scheduledReport": {"name": fresh_name, **base_request},
            "clientToken": fresh_token,
            "resourceTags": [{"key": "env", "value": "sim2real-behavioral"}],
        },
    )["arn"]
    ctx.on_cleanup(lambda: bcm.delete_scheduled_report(arn=fresh_arn))

    # terminal assertion is an independent read at the destination, not the mutating
    # call's own response: the fresh report must be the one and only entry under its
    # name, the rejected different-name attempt must still be absent, and the original
    # (also token-reuse-rejected on retry) must still be exactly what it was.
    by_name = _list_scheduled_reports_by_name(bcm)
    assert by_name.get(fresh_name) == fresh_arn, (
        f"fresh-token report not visible via an independent list read: "
        f"expected {fresh_arn!r}, list shows {by_name.get(fresh_name)!r}"
    )
    assert by_name.get(original_name) == original_arn, (
        f"original report changed identity via an independent list read: "
        f"expected {original_arn!r}, list shows {by_name.get(original_name)!r}"
    )
    assert different_name not in by_name, "a second report was created under the rejected different name"


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
    arn = bcm.create_dashboard(
        name=name,
        widgets=[_cost_widget("W1")],
        resourceTags=[{"key": "env", "value": "sim2real-behavioral"}],
    )["arn"]
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "env", "Value": "sim2real-behavioral"}],
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


def _list_scheduled_reports_by_name(bcm) -> dict[str, str]:
    out: dict[str, str] = {}
    token = None
    while True:
        kwargs = {"nextToken": token} if token else {}
        resp = bcm.list_scheduled_reports(maxResults=100, **kwargs)
        out.update({r["name"]: r["arn"] for r in resp["scheduledReports"]})
        token = resp.get("nextToken")
        if not token:
            break
    return out


def _client_error(fn, *, on_unexpected_success=None) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). An unexpected success raises, naming
    the actual result, so acceptance fails as itself and not as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    if on_unexpected_success is not None:
        on_unexpected_success(result)
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
