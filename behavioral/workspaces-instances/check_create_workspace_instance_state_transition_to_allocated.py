"""create-workspace-instance-state-transition-to-allocated."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-workspace-instance-state-transition-to-allocated"
GROUP = "state-machine"
SERVICES = ["workspaces-instances"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateWorkspaceInstance starts ALLOCATING and transitions to ALLOCATED with a real
    backing EC2 instance; the instance is then visible via the ProvisionStates filter."""
    wsi = ctx.client("workspaces-instances")
    _ensure_service_linked_role(ctx)
    subnet_id, az = _default_subnet(ctx)
    ami_id = _latest_al2_ami(ctx)

    resp = _create_workspace_instance_awaiting_role_propagation(
        wsi, ami_id, subnet_id, timeout_s=60.0, interval_s=5.0
    )
    instance_id = resp["WorkspaceInstanceId"]
    ctx.on_cleanup(lambda: _best_effort_delete(wsi, instance_id))

    initial = wsi.get_workspace_instance(WorkspaceInstanceId=instance_id)
    assert initial["ProvisionState"] in ("ALLOCATING", "ALLOCATED"), initial["ProvisionState"]

    final = _poll_until(
        lambda: wsi.get_workspace_instance(WorkspaceInstanceId=instance_id),
        lambda r: r["ProvisionState"] in ("ALLOCATED", "ERROR_ALLOCATING"),
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert final["ProvisionState"] == "ALLOCATED", final.get("WorkspaceInstanceErrors")

    ec2_instance_id = final["EC2ManagedInstance"]["InstanceId"]
    ec2 = ctx.client("ec2")
    described = ec2.describe_instances(InstanceIds=[ec2_instance_id])
    state = described["Reservations"][0]["Instances"][0]["State"]["Name"]
    assert state in ("pending", "running"), state

    allocated_list = wsi.list_workspace_instances(ProvisionStates=["ALLOCATED"])
    allocated_ids = [w["WorkspaceInstanceId"] for w in allocated_list["WorkspaceInstances"]]
    assert instance_id in allocated_ids, f"{instance_id} not in ALLOCATED list {allocated_ids}"

    deallocated_list = wsi.list_workspace_instances(ProvisionStates=["DEALLOCATED"])
    deallocated_ids = [w["WorkspaceInstanceId"] for w in deallocated_list["WorkspaceInstances"]]
    assert instance_id not in deallocated_ids, f"{instance_id} unexpectedly in DEALLOCATED list {deallocated_ids}"


def _ensure_service_linked_role(ctx):
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="workspaces-instances.amazonaws.com")
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidInput":
            raise


def _create_workspace_instance_awaiting_role_propagation(wsi, ami_id, subnet_id, timeout_s=60.0, interval_s=5.0):
    """A freshly created service-linked role is not always immediately usable by
    CreateWorkspaceInstance; retry the specific ValidationException it raises during that
    propagation window, bounded by a deadline rather than a blind sleep."""
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
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )
        except ClientError as e:
            err = e.response["Error"]
            if err["Code"] != "ValidationException" or "service-linked role" not in err["Message"].lower():
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


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


def _best_effort_delete(wsi, instance_id):
    try:
        wsi.delete_workspace_instance(WorkspaceInstanceId=instance_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
