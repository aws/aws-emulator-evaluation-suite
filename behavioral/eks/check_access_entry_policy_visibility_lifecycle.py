"""access-entry-policy-visibility-lifecycle."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "access-entry-policy-visibility-lifecycle"
GROUP = "e2e"
SERVICES = ["eks"]

_POLICY_ARN = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateAccessPolicy and DisassociateAccessPolicy on an access entry show up in
    ListAssociatedAccessPolicies, the observable association state, not just a 200 response."""
    eks = ctx.client("eks")
    cluster_name = _create_active_cluster(
        ctx, access_config={"authenticationMode": "API_AND_CONFIG_MAP"}
    )
    principal_arn = _create_principal_role(ctx)

    # A brand-new IAM role can take a few seconds to propagate through IAM before EKS's
    # access-entry validation can resolve it; retry the specific "invalid principal" failure
    # mode on a bounded window rather than treating it as a hard error.
    _create_access_entry_with_retry(ctx, cluster_name, principal_arn)
    ctx.on_cleanup(
        lambda: _safe(
            lambda: eks.delete_access_entry(
                clusterName=cluster_name, principalArn=principal_arn
            )
        )
    )

    before = eks.list_associated_access_policies(
        clusterName=cluster_name, principalArn=principal_arn
    )["associatedAccessPolicies"]
    assert before == [], f"expected no associated policies before association, got {before}"

    eks.associate_access_policy(
        clusterName=cluster_name,
        principalArn=principal_arn,
        policyArn=_POLICY_ARN,
        accessScope={"type": "cluster"},
    )

    associated = _poll_until(
        lambda: eks.list_associated_access_policies(
            clusterName=cluster_name, principalArn=principal_arn
        )["associatedAccessPolicies"],
        lambda policies: len(policies) == 1,
        timeout_s=60,
        interval_s=3,
    )
    assert associated[0]["policyArn"] == _POLICY_ARN, (
        f"expected associated policy {_POLICY_ARN}, got {associated[0]['policyArn']}"
    )
    assert associated[0]["accessScope"]["type"] == "cluster", (
        f"expected accessScope type 'cluster', got {associated[0]['accessScope']['type']!r}"
    )

    eks.disassociate_access_policy(
        clusterName=cluster_name, principalArn=principal_arn, policyArn=_POLICY_ARN
    )

    after = _poll_until(
        lambda: eks.list_associated_access_policies(
            clusterName=cluster_name, principalArn=principal_arn
        )["associatedAccessPolicies"],
        lambda policies: len(policies) == 0,
        timeout_s=60,
        interval_s=3,
    )
    assert after == [], f"expected no associated policies after disassociation, got {after}"


# ===== helpers =====


def _error_code(fn: Callable[[], Any]) -> str | None:
    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


_NOT_FOUND = {"ResourceNotFoundException", "NoSuchEntity", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"}


def _safe(fn: Callable[[], Any], release_s: float = 280.0) -> None:
    """Run a teardown call: a resource already gone is fine, DependencyViolation (cluster ENIs still
    being released) is retried every 2 s up to release_s, and every other error raises."""
    deadline = time.monotonic() + release_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in _NOT_FOUND:
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
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
        CidrBlock="10.42.0.0/16",
        TagSpecifications=_tag_specs("vpc", ctx.unique_name("sim2real-eks-vpc-")),
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    subnet_ids = []
    for i, cidr_block in enumerate(("10.42.0.0/24", "10.42.1.0/24")):
        az = azs[i % len(azs)]["ZoneName"]
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=cidr_block,
            AvailabilityZone=az,
            TagSpecifications=_tag_specs("subnet", ctx.unique_name(f"sim2real-eks-subnet{i}-")),
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)
        ctx.on_cleanup(lambda sid=subnet_id: _safe(lambda: ec2.delete_subnet(SubnetId=sid)))
    return vpc_id, subnet_ids


def _create_cluster_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-clusterrole-")
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


def _create_principal_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-principal-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))[
        "Role"
    ]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    return role_arn


def _create_access_entry_with_retry(ctx, cluster_name: str, principal_arn: str) -> None:
    eks = ctx.client("eks")
    deadline = time.monotonic() + 60
    while True:
        try:
            eks.create_access_entry(
                clusterName=cluster_name, principalArn=principal_arn, type="STANDARD"
            )
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if (
                code == "InvalidParameterException"
                and "principal" in msg.lower()
                and time.monotonic() < deadline
            ):
                time.sleep(5)
                continue
            raise


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


def _create_active_cluster(
    ctx,
    access_config: dict[str, Any] | None = None,
    remote_network_config: dict[str, Any] | None = None,
    resources_vpc_config_extra: dict[str, Any] | None = None,
    kubernetes_network_config: dict[str, Any] | None = None,
) -> str:
    _vpc_id, subnet_ids = _create_vpc_and_subnets(ctx)
    role_arn = _create_cluster_role(ctx)
    name = ctx.unique_name("sim2real-eks-")
    resources_vpc_config: dict[str, Any] = {"subnetIds": subnet_ids}
    if resources_vpc_config_extra:
        resources_vpc_config.update(resources_vpc_config_extra)
    kwargs: dict[str, Any] = {
        "name": name,
        "roleArn": role_arn,
        "resourcesVpcConfig": resources_vpc_config,
    }
    if access_config:
        kwargs["accessConfig"] = access_config
    if remote_network_config:
        kwargs["remoteNetworkConfig"] = remote_network_config
    if kubernetes_network_config:
        kwargs["kubernetesNetworkConfig"] = kubernetes_network_config
    _create_cluster_with_retry(ctx, **kwargs)
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(ctx, name))
    _wait_cluster_active(ctx, name)
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
