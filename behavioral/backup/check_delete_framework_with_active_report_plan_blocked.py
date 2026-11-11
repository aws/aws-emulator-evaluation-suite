"""delete-framework-with-active-report-plan-blocked."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-framework-with-active-report-plan-blocked"
GROUP = "overly-permissive"
SERVICES = ["backup"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteFramework on a framework referenced by a report plan fails with ConflictException and
    leaves it intact; once the reference is removed the same call succeeds."""
    backup = ctx.client("backup")
    bucket = _create_bucket(ctx)

    framework_name = _alnum_name(ctx, "sim2realFramework")
    framework_arn = backup.create_framework(
        FrameworkName=framework_name,
        FrameworkDescription="sim2real behavioral fidelity check framework",
        FrameworkControls=[
            {
                "ControlName": "BACKUP_RESOURCES_PROTECTED_BY_BACKUP_PLAN",
                # AWS Backup requires each framework's (controls, scope) combination to be
                # unique in the account, so the control is scoped to a per-run tag.
                "ControlScope": {"Tags": {"sim2real-framework-run": framework_name}},
            }
        ],
        FrameworkTags={"sim2real-check": CHECK},
    )["FrameworkArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: backup.delete_framework(FrameworkName=framework_name)))

    plan_name = _alnum_name(ctx, "sim2realReportPlan")
    _create_report_plan_with_retry(ctx, plan_name, bucket, framework_arn)
    ctx.on_cleanup(lambda: _delete_report_plan_with_retry(ctx, plan_name, raise_on_timeout=False))

    code, message = _error(lambda: backup.delete_framework(FrameworkName=framework_name))
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    assert message == (
        f"Operation failed because of a concurrent update for the framework {framework_name} in "
        f"account {ctx.account}. Try again later."
    ), f"actual_message={message!r}"

    # effect absent: the framework was not deleted
    desc = backup.describe_framework(FrameworkName=framework_name)
    assert desc["FrameworkName"] == framework_name, (
        f"expected framework {framework_name} to still exist after the rejected delete, "
        f"describe_framework returned {desc.get('FrameworkName')!r}"
    )

    # positive control: once the report plan reference is removed, deletion succeeds
    _delete_report_plan_with_retry(ctx, plan_name, raise_on_timeout=True)
    _wait_framework_deletable(ctx, framework_name)
    gone_message = _wait_framework_gone(ctx, framework_name)
    assert gone_message == f"Framework {framework_name} not found in account {ctx.account}.", f"actual_message={gone_message!r}"


def _error(fn):
    """Call fn(); return the ClientError's (code, message). An unexpected success raises,
    so accepting a request AWS refuses fails the check."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_call(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "ResourceNotFoundException"):
            raise


def _alnum_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix + "-")
    return "".join(ch if ch.isalnum() else "" for ch in raw) or prefix


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-backup-rpt-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _safe_call(lambda: s3.delete_bucket(Bucket=name)))
    return name


def _create_report_plan_with_retry(ctx, plan_name, bucket, framework_arn, timeout_s=20, interval_s=5):
    """CreateReportPlan may transiently reject a FrameworkArn while the framework's own
    FrameworkControls deployment is still CREATE_IN_PROGRESS; retry until the framework
    settles rather than blocking up-front on a possibly slow (multi-minute) Config-backed
    deployment that this check's ConflictException-on-delete assertion doesn't depend on."""
    backup = ctx.client("backup")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            backup.create_report_plan(
                ReportPlanName=plan_name,
                ReportDeliveryChannel={"S3BucketName": bucket},
                ReportSetting={"ReportTemplate": "CONTROL_COMPLIANCE_REPORT", "FrameworkArns": [framework_arn]},
                ReportPlanTags={"sim2real-check": CHECK},
            )
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ConflictException", "InvalidParameterValueException"):
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"CreateReportPlan never accepted framework {framework_arn} within {timeout_s}s: {last_err}")


def _wait_framework_deletable(ctx, name: str, timeout_s: float = 210, interval_s: float = 5):
    backup = ctx.client("backup")
    deadline = time.monotonic() + timeout_s
    conflict_message = (
        f"Operation failed because of a concurrent update for the framework {name} in "
        f"account {ctx.account}. Try again later."
    )
    last_code = None
    while time.monotonic() < deadline:
        try:
            backup.delete_framework(FrameworkName=name)
            return
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            last_message = err.response["Error"].get("Message")
        if last_code != "ConflictException" or last_message != conflict_message:
            raise AssertionError(f"unexpected error deleting framework: {last_code} {last_message!r}")
        time.sleep(interval_s)
    raise AssertionError(f"framework {name} still not deletable after {timeout_s}s (last code {last_code})")


def _delete_report_plan_with_retry(ctx, plan_name, timeout_s=30, interval_s=5, raise_on_timeout=True):
    """CreateReportPlan triggers an immediate on-demand report execution; DeleteReportPlan is
    rejected with ConflictException ('pending execution') until that execution finishes.
    Retry until it clears rather than treating the transient rejection as a hard failure."""
    backup = ctx.client("backup")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            backup.delete_report_plan(ReportPlanName=plan_name)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code == "ConflictException":
                last_err = err
                time.sleep(interval_s)
                continue
            if raise_on_timeout:
                raise
            return
    if raise_on_timeout:
        raise AssertionError(f"report plan {plan_name} never became deletable within {timeout_s}s: {last_err}")


def _wait_framework_gone(ctx, name: str, timeout_s: float = 150, interval_s: float = 5):
    """DeleteFramework is accepted synchronously but the framework's removal (and
    DescribeFramework subsequently 404ing) completes asynchronously; poll for it."""
    backup = ctx.client("backup")
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            backup.describe_framework(FrameworkName=name)
            last_code = None
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if last_code == "ResourceNotFoundException":
                return err.response["Error"].get("Message")
        time.sleep(interval_s)
    raise AssertionError(f"framework {name} was not removed within {timeout_s}s (last describe code {last_code})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
