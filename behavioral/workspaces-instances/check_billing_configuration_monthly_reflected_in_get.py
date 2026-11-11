"""billing-configuration-monthly-reflected-in-get."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "billing-configuration-monthly-reflected-in-get"
GROUP = "data-plane"
SERVICES = ["workspaces-instances"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A WorkSpace Instance created with BillingConfiguration.BillingMode=MONTHLY reports
    that same billing mode back on GetWorkspaceInstance, distinct from the HOURLY default a
    plain creation would carry."""
    wsi = ctx.client("workspaces-instances")
    _ensure_service_linked_role(ctx)
    subnet_id, _az = _default_subnet(ctx)
    ami_id = _latest_al2_ami(ctx)
    resource_tags = [{"Key": "owner", "Value": "sim2real"}]

    # CONTROL: the model documents BillingConfiguration as optional, "[defaulting] to hourly
    # billing if not specified" -- this is the baseline the MONTHLY assertion below claims to
    # be "distinct" from. Without this leg, a target whose GetWorkspaceInstance hardcodes
    # BillingMode=MONTHLY regardless of what was requested would still pass this check.
    control_id = _create_workspace_instance_awaiting_role_propagation(
        wsi, ami_id, subnet_id, resource_tags, billing_configuration=None
    )["WorkspaceInstanceId"]
    ctx.on_cleanup(lambda: _delete_instance(wsi, control_id))
    control_got = wsi.get_workspace_instance(WorkspaceInstanceId=control_id)
    assert control_got["BillingConfiguration"]["BillingMode"] == "HOURLY", control_got[
        "BillingConfiguration"
    ]
    _delete_instance(wsi, control_id)

    # COMMITTED SPEND: BillingMode=MONTHLY is documented as "fixed monthly rates", so deleting
    # the instance seconds later does NOT prorate it away -- the month is charged. The mode is
    # what the assertion is about, so it cannot be lowered to HOURLY.
    # MISSING API: the workspaces-instances model has no Update/Modify operation at all
    # (Create/Get/List/Delete plus volumes and tags only), so BillingConfiguration is settable
    # only at creation and there is nothing to register as a revert -- the delete registered
    # below is the whole of the available teardown.
    # RESIDUAL COST PER RUN: one month of one m5.large WorkSpace Instance. The one lever left is
    # the instance type (it is not asserted); ListInstanceTypes enumerates the legal values for
    # this account/Region if an operator wants to pin a smaller one.
    instance_id = _create_workspace_instance_awaiting_role_propagation(
        wsi, ami_id, subnet_id, resource_tags, billing_configuration={"BillingMode": "MONTHLY"}
    )["WorkspaceInstanceId"]
    ctx.on_cleanup(lambda: _delete_instance(wsi, instance_id))

    got = wsi.get_workspace_instance(WorkspaceInstanceId=instance_id)
    assert got["BillingConfiguration"]["BillingMode"] == "MONTHLY", got["BillingConfiguration"]


# ===== helpers =====
def _ensure_service_linked_role(ctx):
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="workspaces-instances.amazonaws.com")
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidInput":
            raise


def _create_workspace_instance_awaiting_role_propagation(
    wsi, ami_id, subnet_id, resource_tags, billing_configuration, timeout_s=60.0, interval_s=5.0
):
    """A freshly created service-linked role is not always immediately usable by
    CreateWorkspaceInstance; retry the specific ValidationException it raises during that
    propagation window, bounded by a deadline rather than a blind sleep."""
    from botocore.exceptions import ClientError

    kwargs = {
        "ManagedInstance": {"ImageId": ami_id, "InstanceType": "m5.large", "SubnetId": subnet_id},
        "Tags": resource_tags,
    }
    if billing_configuration is not None:
        kwargs["BillingConfiguration"] = billing_configuration

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return wsi.create_workspace_instance(**kwargs)
        except ClientError as e:
            err = e.response["Error"]
            if err["Code"] != "ValidationException" or "service-linked role" not in err["Message"].lower():
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


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


def _delete_instance(wsi, instance_id, timeout_s=300.0):
    """Delete an instance; already gone is clean, a ConflictException (state change still in
    progress) is retried every 2 s for up to 300 s, and any other error raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            wsi.delete_workspace_instance(WorkspaceInstanceId=instance_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
