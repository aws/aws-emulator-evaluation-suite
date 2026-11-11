"""delete-workspace-instance-state-transition-to-deallocated."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-workspace-instance-state-transition-to-deallocated"
GROUP = "state-machine"
SERVICES = ["workspaces-instances"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteWorkspaceInstance moves an ALLOCATED instance through DEALLOCATING and the
    instance eventually reports DEALLOCATED (or disappears with ResourceNotFoundException)."""
    wsi = ctx.client("workspaces-instances")
    _ensure_service_linked_role(ctx)
    subnet_id = _create_subnet(ctx)
    ami_id = _latest_al2_ami(ctx)

    instance_id = _create_instance_with_retry(wsi, ami_id, subnet_id)
    deleted = {"done": False}

    def _cleanup():
        if not deleted["done"]:
            try:
                wsi.delete_workspace_instance(WorkspaceInstanceId=instance_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise

    ctx.on_cleanup(_cleanup)

    _poll_until(
        lambda: wsi.get_workspace_instance(WorkspaceInstanceId=instance_id),
        lambda r: r["ProvisionState"] in ("ALLOCATED", "ERROR_ALLOCATING"),
        timeout_s=600.0,
        interval_s=10.0,
    )

    wsi.delete_workspace_instance(WorkspaceInstanceId=instance_id)
    deleted["done"] = True

    final_state = _poll_until_terminal(wsi, instance_id, timeout_s=600.0, interval_s=10.0)
    assert final_state == "DEALLOCATED", final_state


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _poll_until_terminal(wsi, instance_id, timeout_s=600.0, interval_s=10.0):
    """Poll until DEALLOCATED/ERROR_DEALLOCATING, or the resource is purged (NotFound == DEALLOCATED)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        try:
            resp = wsi.get_workspace_instance(WorkspaceInstanceId=instance_id)
            last_state = resp["ProvisionState"]
            if last_state in ("DEALLOCATED", "ERROR_DEALLOCATING"):
                return last_state
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return "DEALLOCATED"
            raise
        time.sleep(interval_s)
    raise AssertionError(f"did not reach a terminal deallocation state within {timeout_s}s; last={last_state}")


def _ensure_service_linked_role(ctx):
    """CreateWorkspaceInstance requires the AWSServiceRoleForWorkspacesInstances service-linked
    role; create it if this account has never done so (adopt if it already exists), then wait
    for IAM's own read-your-writes so a subsequent get_role sees it."""
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    role_name = "AWSServiceRoleForWorkspacesInstances"
    try:
        iam.create_service_linked_role(AWSServiceName="workspaces-instances.amazonaws.com")
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidInput":
            raise

    def _role_visible():
        try:
            iam.get_role(RoleName=role_name)
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                return False
            raise

    _poll_until(_role_visible, lambda visible: visible, timeout_s=60.0, interval_s=3.0)


def _create_instance_with_retry(wsi, ami_id, subnet_id, timeout_s=120.0, interval_s=5.0):
    """The workspaces-instances control plane can take longer than IAM's own read-your-writes to
    recognize a freshly created service-linked role, so CreateWorkspaceInstance can still refuse
    for a window after _ensure_service_linked_role confirms the role exists. Retry through it."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = wsi.create_workspace_instance(
                ManagedInstance={"ImageId": ami_id, "InstanceType": "m5.large", "SubnetId": subnet_id},
                Tags=[{"Key": "owner", "Value": "sim2real"}],
            )
            return resp["WorkspaceInstanceId"]
        except ClientError as e:
            msg = e.response["Error"].get("Message", "")
            if e.response["Error"]["Code"] != "ValidationException" or "service-linked role" not in msg.lower():
                raise
            last_exc = e
            time.sleep(interval_s)
    raise AssertionError(f"service-linked role never became usable within {timeout_s}s: {last_exc}")


def _create_subnet(ctx):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-wsi-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.93.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.93.1.0/24",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    return subnet_id


def _latest_al2_ami(ctx):
    ssm = ctx.client("ssm")
    resp = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )
    return resp["Parameter"]["Value"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
