"""associate-disassociate-volume-roundtrip."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "associate-disassociate-volume-roundtrip"
GROUP = "data-plane"
SERVICES = ["workspaces-instances"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateVolume attaches a real EBS volume to the real underlying EC2 instance
    (observable via ec2:DescribeVolumes attachments), and DisassociateVolume detaches it
    again, leaving the instance running and the volume independently existing."""
    wsi = ctx.client("workspaces-instances")
    ec2 = ctx.client("ec2")
    _ensure_service_linked_role(ctx, "workspaces-instances.amazonaws.com")
    subnet_id, az = _default_subnet(ctx)
    ami_id = _latest_al2_ami(ctx)

    def _create():
        return wsi.create_workspace_instance(
            ManagedInstance={
                "ImageId": ami_id,
                "InstanceType": "m5.large",
                "SubnetId": subnet_id,
                "Placement": {"AvailabilityZone": az},
            },
            Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-wsi-")}],
        )

    instance_id = _create_with_slr_propagation_retry(_create)["WorkspaceInstanceId"]
    ctx.on_cleanup(lambda: _best_effort_delete_instance(wsi, instance_id))

    final = _poll_until(
        lambda: wsi.get_workspace_instance(WorkspaceInstanceId=instance_id),
        lambda r: r["ProvisionState"] in ("ALLOCATED", "ERROR_ALLOCATING"),
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert final["ProvisionState"] == "ALLOCATED", (
        f"expected ProvisionState=ALLOCATED, got {final['ProvisionState']!r} "
        f"errors={final.get('WorkspaceInstanceErrors')!r}"
    )
    ec2_instance_id = final["EC2ManagedInstance"]["InstanceId"]

    volume_id = wsi.create_volume(
        AvailabilityZone=az,
        SizeInGB=10,
        VolumeType="gp3",
        TagSpecifications=[
            {"ResourceType": "volume", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-vol-")}]}
        ],
    )["VolumeId"]
    ctx.on_cleanup(lambda: _best_effort_delete_volume(wsi, volume_id))

    # a freshly created EBS volume is not immediately associable
    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0],
        lambda v: v["State"] == "available",
        timeout_s=120.0,
        interval_s=5.0,
    )

    wsi.associate_volume(WorkspaceInstanceId=instance_id, VolumeId=volume_id, Device="/dev/sdh")

    attached = _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0],
        lambda v: len(v.get("Attachments", [])) == 1,
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert attached["Attachments"][0]["InstanceId"] == ec2_instance_id, (
        f"expected volume {volume_id} attached to {ec2_instance_id}, "
        f"got {attached['Attachments'][0]['InstanceId']!r}"
    )
    assert attached["Attachments"][0]["Device"] == "/dev/sdh", (
        f"expected device /dev/sdh, got {attached['Attachments'][0]['Device']!r}"
    )

    wsi.disassociate_volume(
        WorkspaceInstanceId=instance_id, VolumeId=volume_id, DisassociateMode="FORCE"
    )

    detached = _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0],
        lambda v: len(v.get("Attachments", [])) == 0,
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert detached.get("Attachments", []) == [], (
        f"expected no attachments on {volume_id} after disassociate, got {detached.get('Attachments')!r}"
    )
    assert detached["State"] != "deleted", (
        f"expected volume {volume_id} to independently survive disassociate, got State={detached['State']!r}"
    )


def _create_with_slr_propagation_retry(create_fn, timeout_s=90.0, interval_s=5.0):
    """A freshly-created AWSServiceRoleForWorkspacesInstances is visible via IAM
    immediately but can take up to ~a minute to propagate to the internal permission
    check CreateWorkspaceInstance performs; retry only that specific rejection."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return create_fn()
        except ClientError as e:
            err = e.response["Error"]
            if err["Code"] != "ValidationException" or "service-linked role" not in err["Message"].lower():
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _ensure_service_linked_role(ctx, service_name):
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    try:
        role_name = iam.create_service_linked_role(AWSServiceName=service_name)["Role"][
            "RoleName"
        ]
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidInput":
            raise
        return  # already exists, and therefore already propagated

    def _role_visible():
        try:
            iam.get_role(RoleName=role_name)
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                return False
            raise

    _poll_until(_role_visible, lambda ok: ok, timeout_s=30.0, interval_s=3.0)


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


def _best_effort_delete_volume(wsi, volume_id):
    try:
        wsi.delete_volume(VolumeId=volume_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
