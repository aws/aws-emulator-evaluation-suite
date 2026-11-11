"""e2e-capacity-manager-metrics-flow."""
from __future__ import annotations

import datetime
import json
import time

from behavioral_harness import tags

CHECK = "e2e-capacity-manager-metrics-flow"
GROUP = "e2e"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:ec2-capacity-manager")
def run(ctx) -> None:
    """A monitored tag key goes absent -> activating -> deactivating -> absent, the metric reads
    answer either a well-shaped result or CapacityManager.DataNotAvailable, and a deleted data
    export drops out of DescribeCapacityManagerDataExports."""
    ec2 = ctx.client("ec2")
    s3 = ctx.client("s3")

    from botocore.exceptions import ClientError

    try:
        attrs = ec2.get_capacity_manager_attributes()
        enabled = attrs["CapacityManagerStatus"] == "enabled"
    except ClientError as err:
        if err.response["Error"]["Code"] != "CapacityManager.Disabled":
            raise
        enabled = False

    if not enabled:
        ec2.enable_capacity_manager(OrganizationsAccess=False)
        ctx.on_cleanup(lambda: _unless_gone(ec2.disable_capacity_manager, "CapacityManager.Disabled"))
        _poll_until(
            lambda: ec2.get_capacity_manager_attributes(),
            lambda a: a["CapacityManagerStatus"] == "enabled",
            timeout_s=120,
        )

    # Only one data export is allowed per account -- clear any leaked one THIS
    # check created (its bucket carries the sim2real-cmef- prefix) so it can
    # create its own deterministically. Never delete an export it does not own.
    for stale in ec2.describe_capacity_manager_data_exports()["CapacityManagerDataExports"]:
        if not stale.get("S3BucketName", "").startswith("sim2real-cmef-"):
            raise AssertionError(
                "the account already has a Capacity Manager data export not created by this "
                f"check ({stale['CapacityManagerDataExportId']}, bucket "
                f"{stale.get('S3BucketName')!r}); refusing to delete it"
            )
        _unless_gone(
            lambda sid=stale["CapacityManagerDataExportId"]: ec2.delete_capacity_manager_data_export(
                CapacityManagerDataExportId=sid
            ),
            "InvalidCapacityManagerDataExportId.NotFound",
        )
    if ec2.describe_capacity_manager_data_exports()["CapacityManagerDataExports"]:
        _poll_until(
            lambda: ec2.describe_capacity_manager_data_exports()["CapacityManagerDataExports"],
            lambda lst: lst == [],
            timeout_s=90,
        )

    bucket = ctx.unique_name("sim2real-cmef-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _unless_gone(lambda: s3.delete_bucket(Bucket=bucket), "NoSuchBucket"))

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.capacitymanager.amazonaws.com"},
                "Action": ["s3:PutObject", "s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {
                        "aws:SourceArn": (
                            f"arn:aws:ec2:{ctx.region}:{account_id}:"
                            "capacity-manager-data-export/*"
                        )
                    },
                },
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(bucket_policy))

    export_id = ec2.create_capacity_manager_data_export(
        S3BucketName=bucket, Schedule="hourly", OutputFormat="csv"
    )["CapacityManagerDataExportId"]
    ctx.on_cleanup(
        lambda: _unless_gone(
            lambda: ec2.delete_capacity_manager_data_export(
                CapacityManagerDataExportId=export_id
            ),
            "InvalidCapacityManagerDataExportId.NotFound",
        )
    )
    _poll_until(
        lambda: ec2.describe_capacity_manager_data_exports(
            CapacityManagerDataExportIds=[export_id]
        )["CapacityManagerDataExports"],
        lambda lst: lst != [],
        timeout_s=60,
    )

    tag_key = ctx.unique_name("sim2real-cm-tag-")

    def _find_key():
        keys = ec2.get_capacity_manager_monitored_tag_keys()["CapacityManagerTagKeys"]
        return next((k for k in keys if k["TagKey"] == tag_key), None)

    # --- Before activation: the tag key is not monitored at all. ---
    assert _find_key() is None

    # Activation is asynchronous and, per AWS docs, can take up to 24h to
    # reach "activated" -- so assert the *immediate* documented transition
    # (absent -> activating) rather than waiting out the real pipeline.
    activate_resp = ec2.update_capacity_manager_monitored_tag_keys(
        ActivateTagKeys=[tag_key]
    )
    def _deactivate_if_monitored():
        # The check deactivates the key itself; a second deactivate is only owed if it never ran.
        key = _find_key()
        if key is not None and key["Status"] != "deactivating":
            ec2.update_capacity_manager_monitored_tag_keys(DeactivateTagKeys=[tag_key])

    ctx.on_cleanup(_deactivate_if_monitored)
    activate_entry = next(
        k for k in activate_resp["CapacityManagerTagKeys"] if k["TagKey"] == tag_key
    )
    assert activate_entry["Status"] == "activating"

    # The key must now show up (still "activating") on a fresh read too.
    registered = _poll_until(
        _find_key, lambda k: k is not None, timeout_s=60
    )
    assert registered["TagKey"] == tag_key
    assert registered["Status"] in ("activating", "activated")
    assert registered["CapacityManagerProvided"] is False

    end = datetime.datetime.now(datetime.timezone.utc).replace(
        minute=0, second=0, microsecond=0
    )
    start = end - datetime.timedelta(hours=2)
    cur_attrs = ec2.get_capacity_manager_attributes()
    latest = cur_attrs.get("LatestDatapointTimestamp")
    earliest = cur_attrs.get("EarliestDatapointTimestamp")
    if latest is not None:
        end = latest
        start = max(earliest, end - datetime.timedelta(hours=2)) if earliest else end - datetime.timedelta(hours=2)

    # A Capacity Manager enabled moments ago (as this check just did, above)
    # has no ingested metrics yet, so the metric reads return either a
    # well-shaped result or CapacityManager.DataNotAvailable; any other error
    # fails.
    try:
        dims = ec2.get_capacity_manager_metric_dimensions(
            GroupBy=["account-id"], StartTime=start, EndTime=end, MetricNames=["reservation-total-count"]
        )
    except ClientError as err:
        assert err.response["Error"]["Code"] == "CapacityManager.DataNotAvailable", (
            f"expected DataNotAvailable or success, got {err.response['Error']['Code']}"
        )
        assert err.response["Error"]["Message"] == (
            "Capacity Manager data isn't available yet. Try again later."), err.response["Error"]
        dims = None
    if dims is not None:
        assert isinstance(dims["MetricDimensionResults"], list)
        for entry in dims["MetricDimensionResults"]:
            assert entry.get("AccountId") == account_id, entry

    try:
        data = ec2.get_capacity_manager_metric_data(
            MetricNames=["reservation-total-count"], StartTime=start, EndTime=end, Period=3600
        )
    except ClientError as err:
        assert err.response["Error"]["Code"] == "CapacityManager.DataNotAvailable", (
            f"expected DataNotAvailable or success, got {err.response['Error']['Code']}"
        )
        assert err.response["Error"]["Message"] == (
            "Capacity Manager data isn't available yet. Try again later."), err.response["Error"]
        data = None
    if data is not None:
        assert isinstance(data["MetricDataResults"], list)
        for row in data["MetricDataResults"]:
            dimension = row.get("Dimension") or {}
            assert dimension.get("AccountId") == account_id, row

    # --- Deactivate: the immediate documented transition is -> deactivating,
    # and the key must eventually drop out of the monitored set entirely. ---
    deactivate_resp = ec2.update_capacity_manager_monitored_tag_keys(
        DeactivateTagKeys=[tag_key]
    )
    deactivate_entry = next(
        k for k in deactivate_resp["CapacityManagerTagKeys"] if k["TagKey"] == tag_key
    )
    assert deactivate_entry["Status"] == "deactivating"

    removed = _poll_until(_find_key, lambda k: k is None, timeout_s=180)
    assert removed is None

    # --- Delete the export: it disappears from the describe listing. ---
    ec2.delete_capacity_manager_data_export(CapacityManagerDataExportId=export_id)
    gone = _poll_until(
        lambda: _describe_export_safe(ec2, export_id), lambda lst: lst == [], timeout_s=60
    )
    assert gone == []


# ===== helpers (self-contained) =====
def _unless_gone(fn, *codes) -> None:
    """Only the resource's own not-found *codes* count as already done; any other error raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in codes:
            raise


def _describe_export_safe(ec2, export_id):
    from botocore.exceptions import ClientError

    try:
        return ec2.describe_capacity_manager_data_exports(
            CapacityManagerDataExportIds=[export_id]
        )["CapacityManagerDataExports"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "InvalidCapacityManagerDataExportId.NotFound":
            return []
        raise


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
