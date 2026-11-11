"""report-plan-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "report-plan-lifecycle"
GROUP = "state-machine"
SERVICES = ["backup"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A report plan: create -> describe -> delete -> subsequent describe raises ResourceNotFoundException,
    removed from ListReportPlans, and a second delete of the same name also raises
    ResourceNotFoundException rather than resurrecting or silently succeeding."""
    backup = ctx.client("backup")
    bucket = _create_s3_bucket(ctx)
    name = ctx.unique_name("sim2real_report_").replace("-", "_")

    backup.create_report_plan(
        ReportPlanName=name,
        ReportPlanDescription="sim2real behavioral fidelity check report plan",
        ReportDeliveryChannel={"S3BucketName": bucket, "Formats": ["CSV"]},
        ReportSetting={"ReportTemplate": "BACKUP_JOB_REPORT"},
        ReportPlanTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real_report_"},
    )
    deleted = {"done": False}

    def _cleanup():
        if not deleted["done"]:
            backup.delete_report_plan(ReportPlanName=name)

    ctx.on_cleanup(_cleanup)

    described = backup.describe_report_plan(ReportPlanName=name)["ReportPlan"]
    assert described["ReportSetting"]["ReportTemplate"] == "BACKUP_JOB_REPORT", (
        f"expected ReportTemplate BACKUP_JOB_REPORT, got {described['ReportSetting']!r}"
    )
    assert described["ReportDeliveryChannel"]["S3BucketName"] == bucket, (
        f"expected delivery bucket {bucket!r}, got {described['ReportDeliveryChannel']!r}"
    )

    listed = backup.list_report_plans()["ReportPlans"]
    assert any(p["ReportPlanName"] == name for p in listed), (
        f"expected {name!r} in ListReportPlans, got {[p['ReportPlanName'] for p in listed]!r}"
    )

    _delete_report_plan_with_retry(backup, name)
    deleted["done"] = True

    code, message = _error(lambda: backup.describe_report_plan(ReportPlanName=name), timeout_s=60.0)
    assert code == "ResourceNotFoundException", (
        f"expected DescribeReportPlan on a deleted plan to raise ResourceNotFoundException, got {code!r}"
    )
    expected_message = f"Report plan {name} not found in account {ctx.account}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    listed_after = backup.list_report_plans()["ReportPlans"]
    assert not any(p["ReportPlanName"] == name for p in listed_after), (
        f"expected {name!r} absent from ListReportPlans after delete, got {[p['ReportPlanName'] for p in listed_after]!r}"
    )

    second_delete_code, second_delete_message = _error(lambda: backup.delete_report_plan(ReportPlanName=name))
    assert second_delete_code == "ResourceNotFoundException", (
        f"expected a second delete of an already-deleted report plan to raise "
        f"ResourceNotFoundException, got {second_delete_code!r}"
    )
    expected_second_delete_message = f"Report plan {name} not found in account {ctx.account}."
    assert second_delete_message == expected_second_delete_message, f"expected message {expected_second_delete_message!r}, got {second_delete_message!r}"


def _delete_report_plan_with_retry(backup, name, retries=10, delay=10.0):
    from botocore.exceptions import ClientError

    last_exc = None
    for _ in range(retries):
        try:
            backup.delete_report_plan(ReportPlanName=name)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException":
                raise
            last_exc = exc
            import time

            time.sleep(delay)
    raise last_exc


def _error(fn, *, timeout_s: float = 0.0, interval_s: float = 3.0):
    """Call fn() until it is refused; return the refusal's (code, message). A call that still
    SUCCEEDS once timeout_s has passed raises."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")
        time.sleep(interval_s)


def _create_s3_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-backup-report-")
    kwargs = {"Bucket": bucket}
    # "us-east-1" here is S3's CreateBucket quirk, not a region pin: passing a
    # LocationConstraint of us-east-1 is itself rejected, so it must be omitted
    # for that region while every other region still creates via ctx.region.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]},
    )

    def _cleanup():
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
