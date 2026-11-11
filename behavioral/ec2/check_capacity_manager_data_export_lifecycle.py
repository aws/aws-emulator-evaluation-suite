"""capacity-manager-data-export-lifecycle."""
from __future__ import annotations

import datetime
import json
import time

from behavioral_harness import tags


CHECK = "capacity-manager-data-export-lifecycle"
GROUP = "state-machine"
SERVICES = ["ec2"]



@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ec2-capacity-manager")
def run(ctx) -> None:
    """A data export is listed after CreateCapacityManagerDataExport and gone after its delete,
    while GetCapacityManagerMetricData answers with results or CapacityManager.DataNotAvailable."""
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
        ctx.on_cleanup(lambda: _safe(lambda: ec2.disable_capacity_manager()))
        _poll_until(
            lambda: ec2.get_capacity_manager_attributes(),
            lambda a: a["CapacityManagerStatus"] == "enabled",
            timeout_s=120,
        )

    # Only one data export is allowed per account -- if a prior run leaked
    # one (e.g. process was killed before its cleanup ran), clear it so this
    # check can create its own deterministically.
    for stale in ec2.describe_capacity_manager_data_exports()["CapacityManagerDataExports"]:
        _safe(
            lambda sid=stale["CapacityManagerDataExportId"]: ec2.delete_capacity_manager_data_export(
                CapacityManagerDataExportId=sid
            )
        )
    if ec2.describe_capacity_manager_data_exports()["CapacityManagerDataExports"]:
        _poll_until(
            lambda: ec2.describe_capacity_manager_data_exports()["CapacityManagerDataExports"],
            lambda lst: lst == [],
            timeout_s=90,
        )

    bucket = ctx.unique_name("sim2real-cmde-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: _safe(lambda: _empty_and_delete_bucket(s3, bucket)))

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.capacitymanager.amazonaws.com"},
                "Action": ["s3:PutObject", "s3:GetObject", "s3:ListBucket"],
                "Resource": [
                    f"arn:aws:s3:::{bucket}",
                    f"arn:aws:s3:::{bucket}/*",
                ],
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
        lambda: _safe(
            lambda: ec2.delete_capacity_manager_data_export(
                CapacityManagerDataExportId=export_id
            )
        )
    )

    exports = _poll_until(
        lambda: ec2.describe_capacity_manager_data_exports(
            CapacityManagerDataExportIds=[export_id]
        )["CapacityManagerDataExports"],
        lambda lst: lst != [],
        timeout_s=60,
    )
    assert exports[0]["S3BucketName"] == bucket
    assert exports[0]["Schedule"] == "hourly"
    assert exports[0]["OutputFormat"] == "csv"

    # It must also show up in the unfiltered listing of all exports for the
    # account, not just when explicitly asked for by ID.
    all_ids = [
        e["CapacityManagerDataExportId"]
        for e in ec2.describe_capacity_manager_data_exports()[
            "CapacityManagerDataExports"
        ]
    ]
    assert export_id in all_ids

    end = datetime.datetime.now(datetime.timezone.utc).replace(
        minute=0, second=0, microsecond=0
    )
    start = end - datetime.timedelta(hours=2)

    # Capacity Manager's available datapoint window can lag behind "now" --
    # clamp our query range to what GetCapacityManagerAttributes reports as
    # actually ingested so the metric call itself is exercised deterministically
    # rather than racing against ingestion lag.
    cur_attrs = ec2.get_capacity_manager_attributes()
    latest = cur_attrs.get("LatestDatapointTimestamp")
    earliest = cur_attrs.get("EarliestDatapointTimestamp")
    if latest is not None:
        end = latest
        start = max(earliest, end - datetime.timedelta(hours=2)) if earliest else end - datetime.timedelta(hours=2)

    # An account/region with nothing ever ingested (no Capacity Reservations, no
    # On-Demand/Spot usage) gets a specific typed refusal here rather than an
    # empty result set -- confirmed against real AWS. Any other error is a
    # genuine failure of "the metrics surface keeps working".
    try:
        metric_resp = ec2.get_capacity_manager_metric_data(
            MetricNames=["reservation-total-count"],
            StartTime=start,
            EndTime=end,
            Period=3600,
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "CapacityManager.DataNotAvailable", (
            f"expected success or CapacityManager.DataNotAvailable, got "
            f"{code}: {e.response['Error']['Message'][:300]}"
        )
        assert e.response["Error"]["Message"] == (
            "Capacity Manager data isn't available yet. Try again later."), e.response["Error"]
        metric_resp = None

    if metric_resp is not None:
        assert isinstance(metric_resp["MetricDataResults"], list)

    ec2.delete_capacity_manager_data_export(CapacityManagerDataExportId=export_id)

    gone = _poll_until(
        lambda: _describe_export_safe(ec2, export_id),
        lambda lst: lst == [],
        timeout_s=60,
    )
    assert gone == []


    all_ids_after = [
        e["CapacityManagerDataExportId"]
        for e in ec2.describe_capacity_manager_data_exports()[
            "CapacityManagerDataExports"
        ]
    ]
    assert export_id not in all_ids_after


# Not-found codes of the deletes below; any other failure is raised.
_GONE_CODES = {
    "InvalidCapacityManagerDataExportId.NotFound",
    "NoSuchBucket",
    "CapacityManager.Disabled",
}


def _safe(fn) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in _GONE_CODES:
            raise


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    """Delete every object version and delete marker, then the bucket (DeleteBucket refuses a
    non-empty bucket with BucketNotEmpty)."""
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objects = [
            {"Key": o["Key"], "VersionId": o["VersionId"]}
            for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
        ]
        if objects:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})
    s3.delete_bucket(Bucket=bucket)


def _describe_export_safe(ec2, export_id):
    """DescribeCapacityManagerDataExports raises
    InvalidCapacityManagerDataExportId.NotFound (rather than returning an
    empty list) once the export is fully gone -- normalize that to an empty
    list so pollers can treat it uniformly."""
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
