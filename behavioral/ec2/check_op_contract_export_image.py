"""op-contract-export-image."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-export-image"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ExportImage creates a real, trackable export-image task for a self-owned AMI
    (visible via DescribeExportImageTasks), and rejects a nonexistent ImageId with the
    documented NotFound code."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]

    # Minimal self-owned AMI: empty volume -> snapshot -> register_image.
    vol_name = ctx.unique_name("sim2real-exportimg-vol-")
    vol_id = ec2.create_volume(
        AvailabilityZone=az, Size=1, VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume", "Tags": [{"Key": "Name", "Value": vol_name}]}],
    )["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=vol_id))
    _wait_for(lambda: ec2.describe_volumes(VolumeIds=[vol_id])["Volumes"][0]["State"] == "available")

    snap_name = ctx.unique_name("sim2real-exportimg-snap-")
    snap_id = ec2.create_snapshot(
        VolumeId=vol_id,
        TagSpecifications=[{"ResourceType": "snapshot", "Tags": [{"Key": "Name", "Value": snap_name}]}],
    )["SnapshotId"]
    ctx.on_cleanup(lambda: ec2.delete_snapshot(SnapshotId=snap_id))
    _wait_for(lambda: ec2.describe_snapshots(SnapshotIds=[snap_id])["Snapshots"][0]["State"] == "completed",
              timeout_s=120)

    image_name = ctx.unique_name("sim2real-exportimg-")
    image_id = ec2.register_image(
        Name=image_name,
        Architecture="x86_64",
        RootDeviceName="/dev/xvda",
        VirtualizationType="hvm",
        BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {"SnapshotId": snap_id}}],
        EnaSupport=True,
        TagSpecifications=[{"ResourceType": "image", "Tags": [{"Key": "Name", "Value": image_name}]}],
    )["ImageId"]
    ctx.on_cleanup(lambda: ec2.deregister_image(ImageId=image_id))
    _wait_for(lambda: ec2.describe_images(ImageIds=[image_id])["Images"][0]["State"] == "available")

    bucket = ctx.unique_name("sim2real-exportimg-").lower().replace("_", "-")
    # S3 CreateBucket rejects a LocationConstraint equal to the endpoint's own default
    # region (us-east-1); this is an S3 API quirk, not a region pin of the check itself.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "Name", "Value": bucket}]})

    role_name = ctx.unique_name("sim2real-vmimport-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "vmie.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"sts:Externalid": "vmimport"}},
        }],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "Name", "Value": role_name}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket",
                           "s3:PutObject", "s3:GetBucketAcl"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["ec2:ModifySnapshotAttribute", "ec2:CopySnapshot",
                           "ec2:RegisterImage", "ec2:Describe*"],
                "Resource": "*",
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="vmimport-policy",
                         PolicyDocument=json.dumps(inline_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="vmimport-policy"))

    # --- success path: export task is created and observable (IAM propagation-tolerant) ---
    export_resp = _retry_on_role_propagation(lambda: ec2.export_image(
        ImageId=image_id,
        DiskImageFormat="VMDK",
        S3ExportLocation={"S3Bucket": bucket, "S3Prefix": "exports/"},
        RoleName=role_name,
    ))
    task_id = export_resp["ExportImageTaskId"]

    def _cancel() -> None:
        try:
            ec2.cancel_export_task(ExportTaskId=task_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidExportTaskID.NotFound":
                raise

    ctx.on_cleanup(_cancel)

    assert export_resp["ImageId"] == image_id, (
        f"expected export task's ImageId to echo {image_id!r}, got {export_resp['ImageId']!r}")
    assert export_resp["DiskImageFormat"] == "VMDK", (
        f"expected DiskImageFormat 'VMDK', got {export_resp['DiskImageFormat']!r}")
    assert export_resp["Status"] in ("active", "completed"), (
        f"expected export task Status in ('active', 'completed'), got {export_resp['Status']!r}")

    tasks = ec2.describe_export_image_tasks(ExportImageTaskIds=[task_id])["ExportImageTasks"]
    assert len(tasks) == 1 and tasks[0]["ExportImageTaskId"] == task_id, (
        f"expected exactly one export-image task with id {task_id!r} visible via an "
        f"independent DescribeExportImageTasks read, got {tasks!r}")

    # --- error boundary: nonexistent ImageId ---
    # ExportImage validates ImageId with a generic parameter-validation error rather
    # than the resource-specific InvalidAMIID.NotFound family used by e.g. DescribeImages.
    code, message = _error(lambda: ec2.export_image(
        ImageId="ami-00000000000000000",
        DiskImageFormat="VMDK",
        S3ExportLocation={"S3Bucket": bucket, "S3Prefix": "exports/"},
        RoleName=role_name,
    ))
    assert code == "InvalidParameter", f"expected error code 'InvalidParameter', got {code!r}"
    assert message == 'Invalid id: "ami-00000000000000000"', message


def _retry_on_role_propagation(fn: Callable[[], Any], timeout_s: float = 60.0, interval_s: float = 5.0) -> Any:
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] not in ("AccessDenied", "UnauthorizedOperation", "InvalidParameter"):
                raise
            time.sleep(interval_s)
    raise last_exc  # type: ignore[misc]


def _empty_and_delete_bucket(s3: Any, bucket: str, timeout_s: float = 300.0, interval_s: float = 10.0) -> None:
    """Delete every object the export task wrote, then the bucket; a cancelled export can
    still land an object shortly after cancellation, so retry while the bucket is non-empty."""
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    while True:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
        try:
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "BucketNotEmpty" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _wait_for(predicate: Callable[[], bool], timeout_s: float = 60.0, interval_s: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval_s)
    raise AssertionError("condition not met within timeout")


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn() and return the (code, message) of the ClientError it raises. A call
    that succeeds raises AssertionError, because an emulator accepting what real AWS
    refuses must not read as a mere code mismatch."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
