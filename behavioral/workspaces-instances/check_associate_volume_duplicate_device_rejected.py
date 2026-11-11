"""associate-volume-duplicate-device-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "associate-volume-duplicate-device-rejected"
GROUP = "overly-permissive"
SERVICES = ["workspaces-instances"]
#: All teardowns of one run share one retry deadline (seconds).
_CLEANUP_S = 1200.0


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateVolume at a device name already in use on the instance fails with ValidationException and
    the exact message, leaving the second volume unattached and the first one's attachment untouched;
    the second volume then attaches at another device.
    """
    wsi = ctx.client("workspaces-instances")
    ec2 = ctx.client("ec2")
    _ensure_service_linked_role(ctx)
    subnet_id, az = _default_subnet(ctx)
    ami_id = _latest_al2_ami(ctx)

    instance_id = _create_workspace_instance_retrying_role_propagation(
        wsi, ami_id, subnet_id, az
    )
    ctx.on_cleanup(lambda: _best_effort_delete_instance(wsi, instance_id))

    allocated = _poll_until(
        lambda: wsi.get_workspace_instance(WorkspaceInstanceId=instance_id),
        lambda r: r["ProvisionState"] in ("ALLOCATED", "ERROR_ALLOCATING"),
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert allocated["ProvisionState"] == "ALLOCATED", allocated
    ec2_instance_id = allocated["EC2ManagedInstance"]["InstanceId"]

    volume_tag_specs = [{"ResourceType": "volume", "Tags": [{"Key": "owner", "Value": "sim2real"}]}]
    volume_a = wsi.create_volume(
        AvailabilityZone=az, SizeInGB=8, VolumeType="gp3", TagSpecifications=volume_tag_specs
    )["VolumeId"]
    teardown_deadline: dict = {}
    ctx.on_cleanup(lambda: _disassociate_and_delete(ctx, wsi, instance_id, volume_a, teardown_deadline))
    volume_b = wsi.create_volume(
        AvailabilityZone=az, SizeInGB=8, VolumeType="gp3", TagSpecifications=volume_tag_specs
    )["VolumeId"]
    ctx.on_cleanup(lambda: _disassociate_and_delete(ctx, wsi, instance_id, volume_b, teardown_deadline))

    # a newly-created EBS volume is briefly "creating" before it becomes attachable
    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_a])["Volumes"][0],
        lambda v: v["State"] == "available",
        timeout_s=60.0,
        interval_s=5.0,
    )
    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_b])["Volumes"][0],
        lambda v: v["State"] == "available",
        timeout_s=60.0,
        interval_s=5.0,
    )

    wsi.associate_volume(WorkspaceInstanceId=instance_id, VolumeId=volume_a, Device="/dev/sdf")

    code, message = _error_code_and_message(
        lambda: wsi.associate_volume(
            WorkspaceInstanceId=instance_id, VolumeId=volume_b, Device="/dev/sdf"
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message}"
    assert message == (
        f"Ec2 can't associate volume {volume_b} to instance {ec2_instance_id} "
        "(InvalidParameterValue: Invalid value '/dev/sdf' for unixDevice. "
        "Attachment point /dev/sdf is already in use)"
    ), message

    # effect absent: volume_b remains unattached, volume_a's attachment is unaffected
    described_b = ec2.describe_volumes(VolumeIds=[volume_b])["Volumes"][0]
    attachments_b = described_b.get("Attachments", [])
    assert attachments_b == [], f"expected volume_b unattached, got {attachments_b!r}"
    described_a = ec2.describe_volumes(VolumeIds=[volume_a])["Volumes"][0]
    attachments_a = described_a.get("Attachments", [])
    assert len(attachments_a) == 1, f"expected volume_a's 1 attachment untouched, got {attachments_a!r}"

    # positive control: same volume_b, a free device name, succeeds
    wsi.associate_volume(WorkspaceInstanceId=instance_id, VolumeId=volume_b, Device="/dev/sdg")
    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_b])["Volumes"][0],
        lambda v: len(v.get("Attachments", [])) == 1,
        timeout_s=60.0,
        interval_s=5.0,
    )


def _ensure_service_linked_role(ctx):
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="workspaces-instances.amazonaws.com")
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidInput":
            raise


def _create_workspace_instance_retrying_role_propagation(wsi, ami_id, subnet_id, az):
    from botocore.exceptions import ClientError

    # a freshly-created service-linked role is not immediately usable; retry the specific
    # role-not-ready rejection on a bounded window instead of guessing a fixed propagation delay
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return wsi.create_workspace_instance(
                ManagedInstance={
                    "ImageId": ami_id,
                    "InstanceType": "m5.large",
                    "SubnetId": subnet_id,
                    "Placement": {"AvailabilityZone": az},
                },
                Tags=[{"Key": "owner", "Value": "sim2real"}],
            )["WorkspaceInstanceId"]
        except ClientError as e:
            err = e.response["Error"]
            role_not_ready = err["Code"] == "ValidationException" and "Service-linked role" in err.get(
                "Message", ""
            )
            if not role_not_ready or time.monotonic() >= deadline:
                raise
            time.sleep(5.0)


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection but the call succeeded: {result!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _default_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to launch a WorkSpace Instance")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("no subnet available in shared network")
    subnet = subnets[0]
    return subnet["SubnetId"], subnet["AvailabilityZone"]


def _latest_al2_ami(ctx):
    ssm = ctx.client("ssm")
    resp = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )
    return resp["Parameter"]["Value"]


def _best_effort_delete_instance(wsi, instance_id):
    try:
        wsi.delete_workspace_instance(WorkspaceInstanceId=instance_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _disassociate_and_delete(ctx, wsi, instance_id, volume_id, teardown_deadline):
    """Force-detach the volume, wait until EBS reports it available (detach is asynchronous), then
    delete it, retrying the in-use ConflictException every 2 s to the shared cleanup deadline."""
    deadline = teardown_deadline.setdefault("t", time.monotonic() + _CLEANUP_S)
    try:
        wsi.disassociate_volume(
            WorkspaceInstanceId=instance_id, VolumeId=volume_id, DisassociateMode="FORCE"
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    ec2 = ctx.client("ec2")
    while True:
        try:
            state = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidVolume.NotFound":
                return
            raise
        if state == "available":
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"volume {volume_id} still {state} at the cleanup deadline")
        time.sleep(2)
    while True:
        try:
            wsi.delete_volume(VolumeId=volume_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
