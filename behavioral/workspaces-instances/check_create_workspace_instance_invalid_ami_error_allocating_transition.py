"""create-workspace-instance-invalid-ami-error-allocating-transition."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-workspace-instance-invalid-ami-error-allocating-transition"
GROUP = "overly-permissive"
SERVICES = ["workspaces-instances"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateWorkspaceInstance with a well-formed nonexistent ImageId fails at request time with
    ValidationException and "Invalid AMI ID provided" and adds no instance; a real AMI on the same
    subnet reaches ALLOCATED.
    """
    wsi = ctx.client("workspaces-instances")
    _ensure_service_linked_role(ctx)
    subnet_id, _az = _default_subnet(ctx)
    ami_id = _latest_al2_ami(ctx)

    # positive control: identical parameters with a real AMI succeed. Retried (bounded, not
    # slept) because the service-linked role just adopted/created above needs a few seconds
    # to propagate to the workspaces-instances control plane.
    control_id = _create_with_role_propagation_retry(
        wsi, ami_id, subnet_id
    )["WorkspaceInstanceId"]
    ctx.on_cleanup(lambda: _best_effort_delete(wsi, control_id))
    control_initial = wsi.get_workspace_instance(WorkspaceInstanceId=control_id)
    assert control_initial["ProvisionState"] in ("ALLOCATING", "ALLOCATED"), control_initial["ProvisionState"]
    control_final = _poll_until_allocation_settles(wsi, control_id)
    assert control_final["ProvisionState"] == "ALLOCATED", control_final["ProvisionState"]

    before_ids = _instance_ids(wsi)

    bogus_ami = "ami-0000000000deadbee"  # well-formed 17-hex-char pattern, does not exist in this account
    marker = ctx.unique_name("sim2real-behav-wsi-")
    code, message = _error_detail(
        lambda: wsi.create_workspace_instance(
            ManagedInstance={"ImageId": bogus_ami, "InstanceType": "m5.large", "SubnetId": subnet_id},
            Tags=[{"Key": "Name", "Value": marker}],
        )
    )
    assert code == "ValidationException", (code, message)
    assert message == "Invalid AMI ID provided", message

    created = _tagged_instances(wsi, _instance_ids(wsi) - before_ids, "Name", marker)
    assert created == [], f"the refused create still added instance(s) {created}"


def _instance_ids(wsi):
    """Every listed WorkSpace Instance id, across all pages."""
    ids = set()
    kwargs = {}
    while True:
        page = wsi.list_workspace_instances(**kwargs)
        ids.update(w["WorkspaceInstanceId"] for w in page.get("WorkspaceInstances", []))
        if not page.get("NextToken"):
            return ids
        kwargs = {"NextToken": page["NextToken"]}


def _tagged_instances(wsi, ids, key, value):
    """The instances among ids tagged key=value; one already deleted is not this check's."""
    own = []
    for instance_id in sorted(ids):
        try:
            instance_tags = wsi.list_tags_for_resource(WorkspaceInstanceId=instance_id).get("Tags", [])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                continue
            raise
        if {"Key": key, "Value": value} in instance_tags:
            own.append(instance_id)
    return own


def _ensure_service_linked_role(ctx):
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="workspaces-instances.amazonaws.com")
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidInput":
            raise


def _create_with_role_propagation_retry(wsi, ami_id, subnet_id, timeout_s=60.0, interval_s=5.0):
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return wsi.create_workspace_instance(
                ManagedInstance={"ImageId": ami_id, "InstanceType": "m5.large", "SubnetId": subnet_id}
            )
        except ClientError as e:
            err = e.response["Error"]
            still_propagating = (
                err["Code"] == "ValidationException"
                and "service-linked role" in err.get("Message", "").lower()
            )
            if still_propagating and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _poll_until_allocation_settles(wsi, instance_id, timeout_s=600.0, interval_s=10.0):
    """Poll GetWorkspaceInstance until ProvisionState leaves ALLOCATING; raise on timeout."""
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = wsi.get_workspace_instance(WorkspaceInstanceId=instance_id)
        if last["ProvisionState"] in ("ALLOCATED", "ERROR_ALLOCATING"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{instance_id} still allocating after {timeout_s}s; last={last!r}")


def _latest_al2_ami(ctx):
    ssm = ctx.client("ssm")
    resp = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )
    return resp["Parameter"]["Value"]


def _error_detail(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected ClientError, but the call SUCCEEDED: {result!r}")


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


def _best_effort_delete(wsi, instance_id):
    try:
        wsi.delete_workspace_instance(WorkspaceInstanceId=instance_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
