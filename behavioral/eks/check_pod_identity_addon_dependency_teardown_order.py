"""pod-identity-addon-dependency-teardown-order."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pod-identity-addon-dependency-teardown-order"
GROUP = "e2e"
SERVICES = ["eks"]

_ADDON_NAME = "aws-ebs-csi-driver"
_SERVICE_ACCOUNT = "ebs-csi-controller-sa"
_EBS_CSI_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An add-on-owned Pod Identity association carries the add-on's ownerArn, yet deleting it
    directly succeeds: it then reads ResourceNotFoundException, drops out of DescribeAddon's
    podIdentityAssociations, and the add-on stays independently deletable."""
    eks = ctx.client("eks")
    cluster_name = _create_active_cluster(ctx)
    pod_role_arn = _create_pod_identity_role(ctx, _EBS_CSI_POLICY_ARN)

    addon = eks.create_addon(
        clusterName=cluster_name,
        addonName=_ADDON_NAME,
        podIdentityAssociations=[
            {"serviceAccount": _SERVICE_ACCOUNT, "roleArn": pod_role_arn}
        ],
    )["addon"]
    ctx.on_cleanup(
        lambda: _safe(lambda: eks.delete_addon(clusterName=cluster_name, addonName=_ADDON_NAME))
    )

    addon = _wait_addon_terminal(ctx, cluster_name, _ADDON_NAME)
    assert addon["status"] != "CREATE_FAILED", f"addon failed to create: {addon}"

    # DescribeAddon's podIdentityAssociations field is documented as "array of strings" and
    # is not guaranteed to be a bare 19-character associationId (it may be an ARN); resolve
    # the concrete associationId the same way a caller would -- via ListPodIdentityAssociations
    # filtered to the associations this addon owns.
    association_ids = _poll_until(
        lambda: [
            a["associationId"]
            for a in eks.list_pod_identity_associations(clusterName=cluster_name)[
                "associations"
            ]
        ],
        lambda ids: len(ids) == 1,
        timeout_s=120,
        interval_s=5,
    )
    association_id = association_ids[0]

    owned = eks.describe_pod_identity_association(
        clusterName=cluster_name, associationId=association_id
    )["association"]
    assert owned["ownerArn"] == addon["addonArn"], "association is not reported as addon-owned"
    assert owned["roleArn"] == pod_role_arn, (
        f"expected association roleArn {pod_role_arn!r}, got {owned['roleArn']!r}"
    )

    before_delete = eks.describe_addon(clusterName=cluster_name, addonName=_ADDON_NAME)["addon"]
    before_refs = before_delete.get("podIdentityAssociations") or []
    assert any(association_id in entry for entry in before_refs), (
        f"expected addon to list the association before deletion: {before_refs}"
    )

    # Deleting the addon-owned association directly is accepted on real AWS -- ownership by
    # an add-on does not block DeletePodIdentityAssociation. Assert the actual, observable
    # consequences of that deletion rather than assuming it would be rejected.
    deleted = eks.delete_pod_identity_association(
        clusterName=cluster_name, associationId=association_id
    )["association"]
    assert deleted["associationId"] == association_id, (
        f"expected DeletePodIdentityAssociation to echo associationId {association_id!r}, "
        f"got {deleted['associationId']!r}"
    )

    assoc_gone_msg = f"No service account role association found for ID: {association_id}"
    code_after, msg_after = _error_code(
        lambda: eks.describe_pod_identity_association(
            clusterName=cluster_name, associationId=association_id
        )
    )
    assert code_after == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a deleted pod identity association, got "
        f"{code_after}"
    )
    assert msg_after == assoc_gone_msg, f"describe of a deleted association -> {msg_after!r}"

    # The dead association id is not just unreadable -- a mutation against it also fails
    # with the same specific not-found code, rather than a generic error.
    code_delete_again, msg_delete_again = _error_code(
        lambda: eks.delete_pod_identity_association(
            clusterName=cluster_name, associationId=association_id
        )
    )
    assert code_delete_again == "ResourceNotFoundException", (
        f"expected re-deleting a gone pod identity association to fail with "
        f"ResourceNotFoundException, got {code_delete_again}"
    )
    assert msg_delete_again == assoc_gone_msg, f"re-delete of a deleted association -> {msg_delete_again!r}"

    # Observable consequence on the owning add-on: the association it used to list is gone.
    after_delete = _poll_until(
        lambda: eks.describe_addon(clusterName=cluster_name, addonName=_ADDON_NAME)["addon"],
        lambda a: not any(
            association_id in entry for entry in (a.get("podIdentityAssociations") or [])
        ),
        timeout_s=120,
        interval_s=5,
    )
    assert not any(
        association_id in entry
        for entry in (after_delete.get("podIdentityAssociations") or [])
    ), (
        f"expected addon's podIdentityAssociations to no longer reference the deleted "
        f"association, got {after_delete.get('podIdentityAssociations')}"
    )

    # The add-on itself remains independently deletable once its association is gone.
    eks.delete_addon(clusterName=cluster_name, addonName=_ADDON_NAME)
    _wait_addon_gone(ctx, cluster_name, _ADDON_NAME)

    code_addon_after, msg_addon_after = _error_code(
        lambda: eks.describe_addon(clusterName=cluster_name, addonName=_ADDON_NAME)
    )
    assert code_addon_after == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a deleted addon, got {code_addon_after}"
    )
    assert msg_addon_after == "The requested resource does not exist.", (
        f"describe of a deleted addon -> {msg_addon_after!r}"
    )

    # Same for the addon: a mutation against the deleted addon name also fails, not just
    # describe.
    code_addon_delete_again, msg_addon_delete_again = _error_code(
        lambda: eks.delete_addon(clusterName=cluster_name, addonName=_ADDON_NAME)
    )
    assert code_addon_delete_again == "ResourceNotFoundException", (
        f"expected re-deleting a gone addon to fail with ResourceNotFoundException, got "
        f"{code_addon_delete_again}"
    )
    assert msg_addon_delete_again == "The requested resource does not exist.", (
        f"re-delete of a deleted addon -> {msg_addon_delete_again!r}"
    )


# ===== helpers =====


def _error_code(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its (error code, message). An unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be rejected, but it succeeded")


_GONE = {"NoSuchEntity", "ResourceNotFoundException", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"}


def _safe(fn: Callable[[], Any], timeout_s: float = 300.0) -> None:
    """Teardown delete: an already-gone resource counts as deleted; DependencyViolation or
    ResourceInUseException (a dependency still releasing) is retried every 2 s up to timeout_s;
    anything else raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in _GONE:
                return
            if code not in ("DependencyViolation", "ResourceInUseException") or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 3.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {last!r}")


def _tag_specs(resource_type: str, name: str) -> list[dict[str, Any]]:
    return [
        {
            "ResourceType": resource_type,
            "Tags": [
                {"Key": "Name", "Value": name},
                {"Key": "sim2real", "Value": "eks-behavioral"},
            ],
        }
    ]


def _create_vpc_and_subnets(ctx) -> tuple[str, list[str]]:
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.43.0.0/16",
        TagSpecifications=_tag_specs("vpc", ctx.unique_name("sim2real-behav-eks-vpc-")),
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    subnet_ids = []
    for i, cidr_block in enumerate(("10.43.0.0/24", "10.43.1.0/24")):
        az = azs[i % len(azs)]["ZoneName"]
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=cidr_block,
            AvailabilityZone=az,
            TagSpecifications=_tag_specs("subnet", ctx.unique_name(f"sim2real-behav-eks-subnet{i}-")),
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)
        ctx.on_cleanup(lambda sid=subnet_id: _safe(lambda: ec2.delete_subnet(SubnetId=sid)))
    return vpc_id, subnet_ids


def _create_cluster_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-eks-clusterrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))[
        "Role"
    ]["Arn"]
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    )

    def _cleanup():
        _safe(
            lambda: iam.detach_role_policy(
                RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
            )
        )
        _safe(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_pod_identity_role(ctx, managed_policy_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-eks-podrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "pods.eks.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession"],
            }
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))[
        "Role"
    ]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)

    def _cleanup():
        _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn))
        _safe(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_cluster_with_retry(ctx, **kwargs) -> dict[str, Any]:
    eks = ctx.client("eks")
    deadline = time.monotonic() + 90
    while True:
        try:
            return eks.create_cluster(**kwargs)["cluster"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidParameterException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


def _wait_cluster_active(ctx, name: str, timeout_s: float = 1500.0, interval_s: float = 20.0) -> None:
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = eks.describe_cluster(name=name)["cluster"]["status"]
        if status == "ACTIVE":
            return
        if status == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED while waiting for ACTIVE")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} did not reach ACTIVE within {timeout_s}s (last={status})")


def _delete_cluster_and_wait(ctx, name: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> None:
    eks = ctx.client("eks")
    _safe(lambda: eks.delete_cluster(name=name))
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} was not deleted within {timeout_s}s")


def _create_active_cluster(ctx) -> str:
    _vpc_id, subnet_ids = _create_vpc_and_subnets(ctx)
    role_arn = _create_cluster_role(ctx)
    name = ctx.unique_name("sim2real-behav-eks-")
    _create_cluster_with_retry(
        ctx,
        name=name,
        roleArn=role_arn,
        resourcesVpcConfig={"subnetIds": subnet_ids},
    )
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(ctx, name))
    _wait_cluster_active(ctx, name)
    return name


def _wait_addon_terminal(
    ctx, cluster_name: str, addon_name: str, timeout_s: float = 900.0, interval_s: float = 15.0
) -> dict[str, Any]:
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    addon = None
    while time.monotonic() < deadline:
        addon = eks.describe_addon(clusterName=cluster_name, addonName=addon_name)["addon"]
        if addon["status"] != "CREATING":
            return addon
        time.sleep(interval_s)
    raise AssertionError(f"addon {addon_name} did not leave CREATING within {timeout_s}s: {addon}")


def _wait_addon_gone(
    ctx, cluster_name: str, addon_name: str, timeout_s: float = 600.0, interval_s: float = 10.0
) -> None:
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_addon(clusterName=cluster_name, addonName=addon_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"addon {addon_name} was not deleted within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
