"""hybrid-nodes-cluster-ca-provisioning-teardown."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "hybrid-nodes-cluster-ca-provisioning-teardown"
GROUP = "e2e"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A cluster with remoteNetworkConfig (Hybrid Nodes) auto-provisions one CA that reaches IN_USE
    and distribution COMPLETE, and deleting the cluster takes the CA with it
    (ListCertificateAuthorities then fails ResourceNotFoundException)."""
    eks = ctx.client("eks")
    cluster_name = _create_active_cluster(
        ctx,
        access_config={"authenticationMode": "API"},
        resources_vpc_config_extra={"endpointPublicAccess": True, "endpointPrivateAccess": False},
        remote_network_config={
            "remoteNodeNetworks": [{"cidrs": ["192.168.0.0/16"]}],
            "remotePodNetworks": [{"cidrs": ["172.16.0.0/16"]}],
        },
        kubernetes_network_config={"serviceIpv4Cidr": "10.100.0.0/16"},
    )

    cas = _poll_until(
        lambda: eks.list_certificate_authorities(clusterName=cluster_name)[
            "certificateAuthorities"
        ],
        lambda items: len(items) > 0,
        timeout_s=300,
        interval_s=10,
    )
    assert len(cas) == 1, (
        f"expected exactly one auto-provisioned certificate authority for a freshly created "
        f"hybrid-nodes cluster with no rotation in progress, got {len(cas)}: {cas}"
    )
    ca_id = cas[0]["id"]

    # Poll to a terminal state on each axis (including the failure alternatives), then assert
    # the specific success values -- so a target that reaches a terminal-but-wrong state (e.g.
    # DistributionStatus=FAILED) fails here instead of being masked by a predicate that already
    # baked the success values into what counts as "done".
    active_ca = _poll_until(
        lambda: eks.describe_certificate_authority(
            clusterName=cluster_name, certificateAuthorityId=ca_id
        )["certificateAuthority"],
        lambda ca: ca["signingStatus"] != "ACTIVATING"
        and ca["distributionStatus"] in ("COMPLETE", "FAILED"),
        timeout_s=300,
        interval_s=10,
    )
    assert active_ca["signingStatus"] == "IN_USE", (
        f"expected the auto-provisioned hybrid-nodes CA to reach IN_USE, got "
        f"{active_ca['signingStatus']!r}"
    )
    assert active_ca["distributionStatus"] == "COMPLETE", (
        f"expected the auto-provisioned hybrid-nodes CA's distribution to reach COMPLETE, got "
        f"{active_ca['distributionStatus']!r}"
    )

    # Tear down the cluster and observe the CA go with it: once the cluster is gone, the
    # certificate-authority resource that lived inside it is no longer reachable either.
    _delete_cluster_and_wait(ctx, cluster_name)

    code, message = _error_detail(lambda: eks.list_certificate_authorities(clusterName=cluster_name))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for certificate authorities of a deleted "
        f"cluster, got {code}"
    )
    expected = f"No cluster found for name: {cluster_name}."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


# ===== helpers =====


def _error_detail(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


_GONE = {"NoSuchEntity", "ResourceNotFoundException", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"}


def _safe(fn: Callable[[], Any], timeout_s: float = 300.0) -> None:
    """Teardown delete: an already-gone resource counts as deleted; DependencyViolation (ENIs of a
    deleted cluster still releasing) is retried every 2 s up to timeout_s; anything else raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in _GONE:
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
        CidrBlock="10.45.0.0/16",
        TagSpecifications=_tag_specs("vpc", ctx.unique_name("sim2real-eks-vpc-")),
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    subnet_ids = []
    for i, cidr_block in enumerate(("10.45.0.0/24", "10.45.1.0/24")):
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
