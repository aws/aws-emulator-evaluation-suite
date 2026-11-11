"""create-scheduled-report-idempotent-token-concurrent."""
from __future__ import annotations

import json
import re
import threading
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-scheduled-report-idempotent-token-concurrent"
GROUP = "concurrency"
SERVICES = ["bcm-dashboards"]

IN_PROGRESS_MESSAGE = (
    "A scheduled report creation is already in progress for the provided clientToken. "
    "Please retry after some time."
)
EXISTS_MESSAGE = (
    "A scheduled report with the provided clientToken already exists (ARN: {arn}). Use a "
    "different clientToken to create a new scheduled report, or use the existing report's ARN "
    "to update it."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Parallel CreateScheduledReport calls sharing one clientToken create exactly one report:
    one call succeeds and every other gets ConflictException, either "already in progress" while
    the winner is in flight or "already exists" naming the winner's ARN after it completes."""
    bcm = ctx.client("bcm-dashboards")
    dashboard_arn = _create_dashboard(ctx)
    role_arn = _create_execution_role(ctx)

    sr_name = ctx.unique_name("sim2real-sr-")
    token = ctx.unique_name("sim2real-token-")
    request = {
        "scheduledReport": {
            "name": sr_name,
            "dashboardArn": dashboard_arn,
            "scheduledReportExecutionRoleArn": role_arn,
            "scheduleConfig": {
                "scheduleExpression": "cron(0 8 ? * MON *)",
                "scheduleExpressionTimeZone": "UTC",
            },
        },
        "resourceTags": [{"key": "workflow", "value": "sim2real-idempotent-token-concurrent"}],
        "clientToken": token,
    }

    barrier = threading.Barrier(5)

    def _create(_i: int):
        barrier.wait(timeout=30)
        try:
            return ("ok", _create_scheduled_report_retrying(bcm, request)["arn"])
        except Exception as err:
            from botocore.exceptions import ClientError

            if isinstance(err, ClientError):
                error = err.response["Error"]
                return ("error", (error["Code"], error.get("Message")))
            raise

    with ThreadPoolExecutor(max_workers=5) as pool:
        outcomes = list(pool.map(_create, range(5)))

    successes = [arn for kind, arn in outcomes if kind == "ok"]
    errors = [err for kind, err in outcomes if kind == "error"]

    assert len(successes) == 1, f"expected exactly one winner, got {successes} and {errors!r}"
    assert re.fullmatch(
        r"arn:aws[-a-z0-9]*:bcm-dashboards::[0-9]{12}:scheduled-report/[-a-z0-9]+", successes[0]
    ), f"expected a scheduled-report ARN from CreateScheduledReport, got {successes[0]!r}"
    # Which refusal a loser gets depends on whether it overlapped the winner; both are graded.
    allowed = {
        ("ConflictException", IN_PROGRESS_MESSAGE),
        ("ConflictException", EXISTS_MESSAGE.format(arn=successes[0])),
    }
    assert all(error in allowed for error in errors), (
        f"expected every non-winning call to get ConflictException with an in-progress or "
        f"already-exists message, got {errors!r}"
    )
    assert len(successes) + len(errors) == 5, (
        f"expected all 5 concurrent calls accounted for as ok/error, got {len(successes)} ok "
        f"+ {len(errors)} error = {len(successes) + len(errors)}"
    )

    winning_arn = successes[0]
    ctx.on_cleanup(lambda: bcm.delete_scheduled_report(arn=winning_arn))

    matches = [
        r
        for r in _list_all_scheduled_reports(bcm)
        if r["name"] == sr_name
    ]
    assert len(matches) == 1, f"expected exactly one listed report named {sr_name!r}, got {matches!r}"
    assert matches[0]["arn"] == winning_arn, (
        f"expected the listed report's arn to be the winner {winning_arn!r}, got {matches[0]['arn']!r}"
    )


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
        resourceTags=[{"key": "workflow", "value": "sim2real-idempotent-token-concurrent"}],
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
        Tags=[{"Key": "workflow", "Value": "sim2real-idempotent-token-concurrent"}],
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


def _list_all_scheduled_reports(bcm):
    out = []
    token = None
    while True:
        kwargs = {"nextToken": token} if token else {}
        resp = bcm.list_scheduled_reports(maxResults=100, **kwargs)
        out.extend(resp["scheduledReports"])
        token = resp.get("nextToken")
        if not token:
            break
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

