"""addon-configuration-values-json-round-trip."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "addon-configuration-values-json-round-trip"
GROUP = "data-plane"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAddon's configurationValues (a JSON-encoded string) round-trips through
    DescribeAddon with unicode text and integer fields preserved exactly - no
    re-typing to float/string and no mangling of non-ASCII text."""
    eks = ctx.client("eks")
    cluster_name, k8s_version = _create_active_cluster(ctx)

    addon_versions = eks.describe_addon_versions(addonName="coredns", kubernetesVersion=k8s_version)[
        "addons"
    ]
    if not addon_versions or not addon_versions[0]["addonVersions"]:
        raise AssertionError("no coredns addon version compatible with this cluster's Kubernetes version")
    addon_version = addon_versions[0]["addonVersions"][0]["addonVersion"]

    config_payload = {
        "replicaCount": 3,
        "podDisruptionBudget": {"enabled": True, "maxUnavailable": 1},
        "corefile": (
            ".:53 {\n"
            "    # unicode marker: caf\u00e9 \u2601\ufe0f \u65e5\u672c\u8a9e \u0627\u0644\u0633\u0644\u0627\u0645\n"
            "    errors\n"
            "    health\n"
            "    ready\n"
            "    forward . /etc/resolv.conf\n"
            "    cache 30\n"
            "    loop\n"
            "    reload\n"
            "    loadbalance\n"
            "}\n"
        ),
    }

    eks.create_addon(
        clusterName=cluster_name,
        addonName="coredns",
        addonVersion=addon_version,
        resolveConflicts="OVERWRITE",
        configurationValues=json.dumps(config_payload),
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: _best_effort_delete_addon(ctx, cluster_name, "coredns"))

    described = eks.describe_addon(clusterName=cluster_name, addonName="coredns")["addon"]
    raw = described["configurationValues"]
    assert isinstance(raw, str), "configurationValues must round-trip as a JSON-encoded string"
    round_tripped = json.loads(raw)

    assert round_tripped["replicaCount"] == 3, f"expected replicaCount 3, got {round_tripped['replicaCount']!r}"
    assert isinstance(round_tripped["replicaCount"], int) and not isinstance(
        round_tripped["replicaCount"], bool
    ), "replicaCount must remain an integer, not be coerced to a float or string"
    assert round_tripped["podDisruptionBudget"] == {"enabled": True, "maxUnavailable": 1}, (
        f"podDisruptionBudget mutated: {round_tripped['podDisruptionBudget']!r}"
    )
    assert round_tripped["corefile"] == config_payload["corefile"], (
        "unicode text inside the corefile string must be preserved byte-for-byte"
    )

    # A second read must be stable (not merely a lucky first response).
    described_again = eks.describe_addon(clusterName=cluster_name, addonName="coredns")["addon"]
    reread = json.loads(described_again["configurationValues"])
    assert reread == round_tripped, f"configurationValues changed between reads: {reread!r} != {round_tripped!r}"


# ===== helpers =====


def _iam_trust_policy(service: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}
            ],
        }
    )


def _create_cluster_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-eks-clusterrole-")
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_iam_trust_policy("eks.amazonaws.com"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    iam.attach_role_policy(RoleName=name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")

    def _cleanup() -> None:
        try:
            iam.detach_role_policy(RoleName=name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _default_vpc_subnets(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az: dict[str, str] = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        subnet_ids = list(by_az.values())
        if len(subnet_ids) >= 2:
            return subnet_ids[:3]
    # No usable shared network in this account/region - provision a dedicated one
    # instead of failing; a freshly provisioned account may not have the shared network.
    return _create_dedicated_vpc_subnets(ctx)


def _create_dedicated_vpc_subnets(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.43.0.0/16")["Vpc"]["VpcId"]
    ec2.create_tags(
        Resources=[vpc_id],
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-vpc-")}, {"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ]
    ][:2]
    if len(azs) < 2:
        raise AssertionError(f"region reports fewer than 2 available availability zones ({azs!r}); cannot host an EKS control plane")

    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.43.{i}.0/24", AvailabilityZone=az)["Subnet"]["SubnetId"]
        ec2.create_tags(
            Resources=[subnet_id],
            Tags=[
                {"Key": "Name", "Value": ctx.unique_name(f"sim2real-eks-subnet-{i}-")},
                {"Key": "sim2real-check", "Value": CHECK},
            ],
        )
        ctx.on_cleanup(lambda sid=subnet_id: ec2.delete_subnet(SubnetId=sid))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _create_cluster_with_retry(ctx, name: str, role_arn: str, subnet_ids: list[str], version: str | None = None):
    eks = ctx.client("eks")
    kwargs: dict[str, Any] = dict(
        name=name,
        roleArn=role_arn,
        resourcesVpcConfig={"subnetIds": subnet_ids},
        tags={"sim2real-check": CHECK},
    )
    if version:
        kwargs["version"] = version
    # A brand-new role is rejected until IAM propagates it: retry every 2 s up to 80 s, capped by
    # the run's remaining time.
    deadline = time.monotonic() + 80.0
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + max(1.0, left - 5.0))
    while True:
        try:
            return eks.create_cluster(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("InvalidParameterException", "ClientException"):
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"create_cluster kept failing (likely IAM propagation lag): {exc}") from exc
        time.sleep(2)


def _wait_cluster_active(ctx, name: str, timeout_s: float = 1200.0, interval_s: float = 20.0) -> str:
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cluster = eks.describe_cluster(name=name)["cluster"]
        status = cluster["status"]
        if status == "ACTIVE":
            return cluster["version"]
        if status == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED status while waiting for ACTIVE")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} did not become ACTIVE within {timeout_s}s")


def _create_active_cluster(ctx) -> tuple[str, str]:
    eks = ctx.client("eks")
    role_arn = _create_cluster_role(ctx)
    subnet_ids = _default_vpc_subnets(ctx)
    name = ctx.unique_name("sim2real-eks-cluster-")
    _create_cluster_with_retry(ctx, name, role_arn, subnet_ids)

    def _delete() -> None:
        try:
            eks.delete_cluster(name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            try:
                eks.describe_cluster(name=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
                return
            time.sleep(15)

    ctx.on_cleanup(_delete)
    version = _wait_cluster_active(ctx, name)
    return name, version


def _best_effort_delete_addon(ctx, cluster_name: str, addon_name: str) -> None:
    eks = ctx.client("eks")
    try:
        eks.delete_addon(clusterName=cluster_name, addonName=addon_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
