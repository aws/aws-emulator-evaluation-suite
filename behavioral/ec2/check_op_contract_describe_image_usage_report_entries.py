"""op-contract-describe-image-usage-report-entries."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-image-usage-report-entries"
GROUP = "error-semantics"
SERVICES = ["ec2"]
_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags(
    "axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """DescribeImageUsageReportEntries for a created report returns an empty entry list and accepts the
    resource-type filter; an unrecognized filter name fails with InternalError and DryRun answers
    DryRunOperation, each with its exact message."""
    ec2 = ctx.client("ec2")

    instance_id = _run_tagged_instance(ctx)
    image_id = ec2.create_image(
        InstanceId=instance_id,
        Name=ctx.unique_name("sim2real-behav-ami-"),
        NoReboot=True,
        TagSpecifications=[_tag_spec(ctx, "image")],
    )["ImageId"]

    def _cleanup_image():
        try:
            ec2.deregister_image(ImageId=image_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "InvalidAMIID.NotFound",
                "InvalidAMIID.Unavailable",
            ):
                raise
        # CreateImage's snapshots are found by the image id in their description at teardown
        # time: the image's own block device mappings are empty while it is still pending.
        snapshots = ec2.describe_snapshots(
            OwnerIds=["self"], Filters=[{"Name": "description", "Values": [f"*{image_id}*"]}]
        )["Snapshots"]
        for snapshot in snapshots:
            _delete_snapshot(ec2, snapshot["SnapshotId"])

    ctx.on_cleanup(_cleanup_image)

    report_id = ec2.create_image_usage_report(
        ImageId=image_id,
        ResourceTypes=[{"ResourceType": "ec2:Instance"}],
        TagSpecifications=[
            {
                "ResourceType": "image-usage-report",
                "Tags": [{"Key": "sim2real", "Value": CHECK}],
            }
        ],
    )["ReportId"]
    ctx.on_cleanup(lambda: ec2.delete_image_usage_report(ReportId=report_id))

    _wait_for_report_available(ec2, report_id)

    # Independent read scoped to the report created above: it lists no entries because no other account
    # uses the image.
    resp = ec2.describe_image_usage_report_entries(ReportIds=[report_id])
    assert isinstance(resp.get("ImageUsageReportEntries"), list)
    assert resp["ImageUsageReportEntries"] == [], (
        f"expected no usage entries for a report with no cross-account usage, "
        f"got {resp['ImageUsageReportEntries']!r}"
    )
    assert resp.get("NextToken") in (None, "")

    # The resource-type filter is honored against the real report without error.
    filtered = ec2.describe_image_usage_report_entries(
        ReportIds=[report_id], Filters=[{"Name": "resource-type", "Values": ["ec2:Instance"]}]
    )
    assert isinstance(filtered.get("ImageUsageReportEntries"), list)

    # Error boundary: an unrecognized filter name fails with InternalError on this operation, unlike the
    # InvalidFilter that DescribeImageUsageReports returns for the same filter.
    code, message = _error(
        lambda: ec2.describe_image_usage_report_entries(
            Filters=[{"Name": "sim2real-bogus-filter", "Values": ["x"]}]
        )
    )
    assert code == "InternalError", f"expected InternalError, got {code!r}"
    expected = "An internal error has occurred"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # DryRun short-circuits before the check is performed.
    dry_code, dry_message = _error(lambda: ec2.describe_image_usage_report_entries(DryRun=True))
    assert dry_code == "DryRunOperation", f"expected DryRunOperation, got {dry_code!r}"
    assert dry_message == _DRY_RUN_MESSAGE, f"expected message {_DRY_RUN_MESSAGE!r}, got {dry_message!r}"


def _wait_for_report_available(ec2, report_id, timeout_s=120, interval_s=5):
    """CreateImageUsageReport returns while the report is still pending; poll until it is available
    and raise on timeout rather than query entries of a report that never became available."""
    deadline = time.monotonic() + timeout_s
    last_state = "missing"
    while time.monotonic() < deadline:
        reports = ec2.describe_image_usage_reports(ReportIds=[report_id]).get("ImageUsageReports", [])
        if reports:
            last_state = reports[0]["State"]
            if last_state == "available":
                return
        time.sleep(interval_s)
    raise AssertionError(
        f"report {report_id} did not reach 'available' within {timeout_s}s (last state: {last_state})"
    )


def _error(fn):
    """Return fn()'s (code, message); a success raises, never reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _tag_spec(ctx, resource_type):
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-behav-{resource_type}-")}],
    }


def _latest_al2023_ami(ctx):
    ec2 = ctx.client("ec2")
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-2023.*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no Amazon Linux 2023 AMI visible in this region")
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _run_tagged_instance(ctx):
    ec2 = ctx.client("ec2")
    ami_id = _latest_al2023_ami(ctx)
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[_tag_spec(ctx, "instance")],
        SubnetId=ctx.network().subnet_ids[0],
    )
    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    waiter = ec2.get_waiter("instance_running")
    waiter.wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 100})
    return instance_id


def _delete_snapshot(ec2, snapshot_id, timeout_s=300.0, interval_s=10.0):
    """Delete an AMI's snapshot, retrying while the just-deregistered image still holds it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_snapshot(SnapshotId=snapshot_id)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidSnapshot.NotFound":
                return
            if time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
