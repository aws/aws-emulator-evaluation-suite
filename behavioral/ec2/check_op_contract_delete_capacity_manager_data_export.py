"""op-contract-deleteCapacityManagerDataExport."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "op-contract-deleteCapacityManagerDataExport"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-capacity-manager")
def run(ctx) -> None:
    """DeleteCapacityManagerDataExport: success removes a scheduled export configuration;
    DryRun short-circuits the delete before it takes effect."""
    ec2 = ctx.client("ec2")
    s3 = ctx.client("s3")
    if not hasattr(ec2, "create_capacity_manager_data_export") or not hasattr(
        ec2, "delete_capacity_manager_data_export"
    ):
        raise AssertionError("installed botocore lacks Capacity Manager data export operations")

    _ensure_capacity_manager_enabled(ctx, ec2)

    bucket = ctx.unique_name("sim2real-capmgr-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    # CreateCapacityManagerDataExport requires the bucket to explicitly authorize the
    # Capacity Manager service principal -- without this, real AWS rejects the create with
    # InvalidParameterValue ("Can't access the S3 bucket") before an export ever exists.
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

    # Error boundary: DryRun must short-circuit before the delete is applied.
    err = _client_error(
        lambda: ec2.delete_capacity_manager_data_export(
            CapacityManagerDataExportId=export_id, DryRun=True
        )
    )
    assert err.get("Code") == "DryRunOperation", f"expected DryRunOperation, got {err!r}"
    assert err.get("Message") == _DRY_RUN_MESSAGE, f"unexpected DryRun message: {err!r}"

    resp = ec2.delete_capacity_manager_data_export(CapacityManagerDataExportId=export_id)
    assert resp["CapacityManagerDataExportId"] == export_id

    # An independent read at the destination confirms the export is actually gone,
    # not just that the mutating call's own response said so.
    remaining = _describe_export_safe(ec2, export_id)
    assert remaining == [], f"expected export gone from Describe listing, got {remaining!r}"

    # Error boundary: deleting the now-nonexistent export again is rejected with the
    # specific not-found code, not merely "some error".
    err2 = _client_error(
        lambda: ec2.delete_capacity_manager_data_export(CapacityManagerDataExportId=export_id)
    )
    assert err2.get("Code") == "InvalidCapacityManagerDataExportId.NotFound", (
        f"expected InvalidCapacityManagerDataExportId.NotFound, got {err2!r}"
    )
    assert err2.get("Message") == f"The capacity-manager-data-export ID '{export_id}' does not exist", (
        f"unexpected not-found message: {err2!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _describe_export_safe(ec2, export_id):
    """DescribeCapacityManagerDataExports raises InvalidCapacityManagerDataExportId.NotFound
    (rather than returning an empty list) once the export is fully gone -- normalize that to
    an empty list so the terminal read is uniform."""
    from botocore.exceptions import ClientError

    try:
        return ec2.describe_capacity_manager_data_exports(
            CapacityManagerDataExportIds=[export_id]
        )["CapacityManagerDataExports"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidCapacityManagerDataExportId.NotFound":
            return []
        raise


def _ensure_capacity_manager_enabled(ctx, ec2):
    """Capacity Manager is an account/region-level setting, disabled by default on a fresh
    account. That makes it a prerequisite this check owns, not a genuinely-absent one:
    create-or-adopt it like any other prerequisite, and only disable it again in cleanup if
    this run is the one that turned it on."""
    from botocore.exceptions import ClientError

    try:
        attrs = ec2.get_capacity_manager_attributes()
        enabled = attrs["CapacityManagerStatus"] == "enabled"
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "CapacityManager.Disabled":
            raise
        enabled = False

    if enabled:
        return

    ec2.enable_capacity_manager(OrganizationsAccess=False)
    ctx.on_cleanup(lambda: _safe(lambda: ec2.disable_capacity_manager()))
    _poll_until(
        lambda: ec2.get_capacity_manager_attributes(),
        lambda a: a["CapacityManagerStatus"] == "enabled",
        timeout_s=120,
    )


def _safe(fn) -> None:
    fn()


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
