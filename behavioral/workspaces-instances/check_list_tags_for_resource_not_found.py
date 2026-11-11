"""list-tags-for-resource-not-found."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-tags-for-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["workspaces-instances"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource returns a real WorkspaceInstance's owner tag, and fails with
    ResourceNotFoundException and the exact message for a well-formed never-created id.
    """
    wsi = ctx.client("workspaces-instances")
    subnet_id = _own_subnet(ctx)
    ami_id = _latest_al2_ami(ctx)
    _ensure_service_linked_role(ctx)

    instance_id = _create_instance_tolerating_slr_propagation(
        wsi, ami_id, subnet_id
    )
    ctx.on_cleanup(lambda: _delete_instance_and_wait(wsi, instance_id))

    control = wsi.list_tags_for_resource(WorkspaceInstanceId=instance_id)["Tags"]
    assert {"Key": "owner", "Value": "sim2real"} in control, control

    bogus_id = "wsinst-00000000notreal"
    error = _error(lambda: wsi.list_tags_for_resource(WorkspaceInstanceId=bogus_id))
    expected_error = ("ResourceNotFoundException", "Workspace instance is not found")
    assert error == expected_error, error


def _own_subnet(ctx):
    """A VPC and subnet this check creates, in an AZ that offers the instance type."""
    ec2 = ctx.client("ec2")
    offered = ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": ["m5.large"]}],
    )["InstanceTypeOfferings"]
    az = sorted(o["Location"] for o in offered)[0]
    name_tags = [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-wsi-")}]
    vpc_id = ec2.create_vpc(
        CidrBlock="10.0.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": name_tags}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.0.1.0/24", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": name_tags}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_subnet(SubnetId=subnet_id)))
    return subnet_id


def _retry_dependency(fn, timeout_s=600.0, interval_s=10.0):
    """Retry a VPC/subnet delete while a terminating instance's interface still holds it."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            if e.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _latest_al2_ami(ctx):
    ssm = ctx.client("ssm")
    resp = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )
    return resp["Parameter"]["Value"]


def _ensure_service_linked_role(ctx):
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="workspaces-instances.amazonaws.com")
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidInput":
            raise


def _create_instance_tolerating_slr_propagation(wsi, ami_id, subnet_id, timeout_s=90.0, interval_s=5.0):
    """A freshly-created AWSServiceRoleForWorkspacesInstances is not usable by
    CreateWorkspaceInstance for a short window after creation; retry only that
    specific ValidationException, bounded, rather than trusting a bare sleep."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return wsi.create_workspace_instance(
                ManagedInstance={
                    "ImageId": ami_id,
                    "InstanceType": "m5.large",
                    "SubnetId": subnet_id,
                },
                Tags=[{"Key": "owner", "Value": "sim2real"}],
            )["WorkspaceInstanceId"]
        except ClientError as e:
            err = e.response["Error"]
            slr_not_ready = (
                err["Code"] == "ValidationException"
                and "Service-linked role is required" in err.get("Message", "")
            )
            if not slr_not_ready or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _delete_instance_and_wait(wsi, instance_id, timeout_s=600.0, interval_s=10.0):
    """Delete the instance once it has left ALLOCATING, then wait until it is gone, so its subnet
    can be deleted after it."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            state = wsi.get_workspace_instance(WorkspaceInstanceId=instance_id)["ProvisionState"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if state != "ALLOCATING":
            break
        time.sleep(interval_s)
    try:
        wsi.delete_workspace_instance(WorkspaceInstanceId=instance_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            state = wsi.get_workspace_instance(WorkspaceInstanceId=instance_id)["ProvisionState"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if state == "DEALLOCATED":
            return
        if state == "ERROR_DEALLOCATING":
            raise AssertionError(f"workspace instance {instance_id} failed to deallocate")
        time.sleep(interval_s)
    raise AssertionError(f"workspace instance {instance_id} was not deleted within {timeout_s}s")


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
