"""create-workspace-instance-duplicate-client-token-conflicting-params-rejected."""
from __future__ import annotations


from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-workspace-instance-duplicate-client-token-conflicting-params-rejected"
GROUP = "overly-permissive"
SERVICES = ["workspaces-instances"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A reused CreateWorkspaceInstance ClientToken is rejected with ConflictException whether the
    replay's parameters differ or match exactly, and neither replay creates a second instance."""
    wsi = ctx.client("workspaces-instances")
    _ensure_service_linked_role(ctx)
    subnet_id, _az = _default_subnet(ctx)
    ami_id = _latest_al2_ami(ctx)
    token = ctx.unique_name("sim2real-tok-")[:64]
    resource_tags = [{"Key": "sim2real-check", "Value": CHECK}]

    first = _create_instance_once_slr_is_effective(
        wsi,
        ClientToken=token,
        ManagedInstance={"ImageId": ami_id, "InstanceType": "m5.large", "SubnetId": subnet_id},
        Tags=resource_tags,
    )
    instance_id = first["WorkspaceInstanceId"]
    ctx.on_cleanup(lambda: _best_effort_delete(wsi, instance_id))

    # same token, different InstanceType -> rejected with ConflictException, no second resource
    conflicting_code, conflicting_message = _error(
        lambda: wsi.create_workspace_instance(
            ClientToken=token,
            ManagedInstance={
                "ImageId": ami_id,
                "InstanceType": "m5.xlarge",
                "SubnetId": subnet_id,
            },
        )
    )
    assert conflicting_code == "ConflictException", (
        f"reusing ClientToken {token!r} with a different InstanceType must be rejected with "
        f"ConflictException; got {conflicting_code!r}: {conflicting_message}"
    )
    assert conflicting_message == "The client token provided does not match the request", (
        conflicting_message
    )

    listing = wsi.list_workspace_instances(ProvisionStates=["ALLOCATING", "ALLOCATED"])
    matching = [w for w in listing["WorkspaceInstances"] if w["WorkspaceInstanceId"] == instance_id]
    assert len(matching) == 1, (
        f"the rejected conflicting-params replay must create no second resource; expected "
        f"exactly 1 listing for {instance_id!r}, got {len(matching)}"
    )

    # same token, IDENTICAL parameters -> also rejected with ConflictException: the token is
    # single-use, not an idempotency key.
    identical_code, identical_message = _error(
        lambda: wsi.create_workspace_instance(
            ClientToken=token,
            ManagedInstance={"ImageId": ami_id, "InstanceType": "m5.large", "SubnetId": subnet_id},
            Tags=resource_tags,
        )
    )
    assert identical_code == "ConflictException", (
        f"reusing ClientToken {token!r} with byte-identical parameters must also be rejected "
        f"with ConflictException (ClientToken is single-use here); got {identical_code!r}: "
        f"{identical_message}"
    )
    assert identical_message == "The client token provided does not match the request", (
        identical_message
    )

    # independent read at the destination: the rejected identical-params replay must not have
    # created a second resource either, and the original must still be the only match
    final_listing = wsi.list_workspace_instances(ProvisionStates=["ALLOCATING", "ALLOCATED"])
    final_matching = [
        w for w in final_listing["WorkspaceInstances"] if w["WorkspaceInstanceId"] == instance_id
    ]
    assert len(final_matching) == 1, (
        f"the rejected identical-params replay must still leave exactly 1 resource for "
        f"{instance_id!r} visible via ListWorkspaceInstances, got {len(final_matching)}"
    )


# ===== helpers =====
def _ensure_service_linked_role(ctx):
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="workspaces-instances.amazonaws.com")
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidInput":
            raise


def _create_instance_once_slr_is_effective(wsi, **kwargs):
    """A freshly created (or freshly-discovered-existing) service-linked role is not
    instantly effective for CreateWorkspaceInstance; retry the specific "Service-linked
    role is required" ValidationException on a bounded backoff rather than trusting IAM's
    own read-your-writes, which is not what is eventually consistent here."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 120.0
    while True:
        try:
            return wsi.create_workspace_instance(**kwargs)
        except ClientError as e:
            error = e.response["Error"]
            if error["Code"] != "ValidationException" or "service-linked role" not in error.get(
                "Message", ""
            ).lower():
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    "the workspaces-instances service-linked role never became effective "
                    "for CreateWorkspaceInstance within 120s"
                ) from e
            time.sleep(2)


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


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


def _best_effort_delete(wsi, instance_id, timeout_s=300.0):
    """Delete the instance; already gone is clean, the ConflictException refused while it is
    still Allocating is retried every 2 s for up to 300 s, and any other error raises."""
    import time

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            wsi.delete_workspace_instance(WorkspaceInstanceId=instance_id)
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
