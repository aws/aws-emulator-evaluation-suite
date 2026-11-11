"""op-contract-delete-image-usage-report."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-delete-image-usage-report"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteImageUsageReport with DryRun answers DryRunOperation and a malformed ID fails with
    InvalidImageUsageReportId.Malformed; a created report deletes, no longer describes, and a repeat
    delete fails with InvalidImageUsageReportId.NotFound (exact messages)."""
    ec2 = ctx.client("ec2")
    fake_id = "ir-00000000000000000"

    dry_run_code, dry_run_message = _error(lambda: ec2.delete_image_usage_report(ReportId=fake_id, DryRun=True))
    assert dry_run_code == "DryRunOperation", f"expected DryRunOperation, got {dry_run_code!r}"
    assert dry_run_message == "Request would have succeeded, but DryRun flag is set.", dry_run_message

    code, message = _error(lambda: ec2.delete_image_usage_report(ReportId=fake_id))
    assert code == "InvalidImageUsageReportId.Malformed", f"unexpected error code {code!r}"
    assert message == f"The image-usage-report ID '{fake_id}' is malformed", message

    image_id = _owned_or_created_image(ctx, ec2)
    report = ec2.create_image_usage_report(
        ImageId=image_id,
        ResourceTypes=[{"ResourceType": "ec2:Instance"}],
    )
    report_id = report["ReportId"]
    ctx.on_cleanup(lambda: _ignore(lambda: ec2.delete_image_usage_report(ReportId=report_id)))

    resp = ec2.delete_image_usage_report(ReportId=report_id)
    assert resp["Return"] is True

    remaining = ec2.describe_image_usage_reports(ReportIds=[report_id]).get("ImageUsageReports", [])
    assert not remaining, f"expected report {report_id} to be gone after delete, got {remaining!r}"

    repeat_code, repeat_message = _error(lambda: ec2.delete_image_usage_report(ReportId=report_id))
    assert repeat_code == "InvalidImageUsageReportId.NotFound", f"unexpected error code {repeat_code!r}"
    assert repeat_message == f"The image-usage-report ID '{report_id}' does not exist", repeat_message


def _owned_or_created_image(ctx, ec2):
    owned_images = ec2.describe_images(Owners=["self"], MaxResults=5).get("Images", [])
    if owned_images:
        return owned_images[0]["ImageId"]
    return _create_image(ctx, ec2)


def _create_image(ctx, ec2):
    base_images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-2023.*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not base_images:
        raise AssertionError("no Amazon Linux 2023 AMI visible in this region")
    base_images.sort(key=lambda i: i["CreationDate"], reverse=True)
    base_ami_id = base_images[0]["ImageId"]

    resp = ec2.run_instances(
        ImageId=base_ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-instance-")}],
            }
        ],
        SubnetId=ctx.network().subnet_ids[0],
    )
    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _ignore(lambda: ec2.terminate_instances(InstanceIds=[instance_id])))
    ec2.get_waiter("instance_running").wait(
        InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 100}
    )

    image_id = ec2.create_image(
        InstanceId=instance_id, Name=ctx.unique_name("sim2real-behav-ami-"), NoReboot=True
    )["ImageId"]
    described_image = ec2.describe_images(ImageIds=[image_id])["Images"][0]
    snapshot_ids = [
        m["Ebs"]["SnapshotId"]
        for m in described_image.get("BlockDeviceMappings", [])
        if "Ebs" in m and "SnapshotId" in m["Ebs"]
    ]

    def _cleanup_image():
        _ignore(lambda: ec2.deregister_image(ImageId=image_id))
        for snapshot_id in snapshot_ids:
            _ignore(lambda: ec2.delete_snapshot(SnapshotId=snapshot_id))

    ctx.on_cleanup(_cleanup_image)
    return image_id


def _error(fn):
    """Call fn() and return the (code, message) of the error it raises. A call
    that SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must
    not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _ignore(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidAMIID.NotFound",
            "InvalidAMIID.Unavailable",
            "InvalidImageUsageReportId.NotFound",
            "InvalidInstanceID.NotFound",
            "InvalidSnapshot.NotFound",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
