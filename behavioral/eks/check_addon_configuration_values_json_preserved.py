"""addon-configuration-values-json-preserved."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "addon-configuration-values-json-preserved"
GROUP = "state-machine"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An addon's configurationValues JSON (nested objects, ints, special chars) is persisted unmodified across describe/update."""
    eks = ctx.client("eks")
    cluster = _create_active_cluster(ctx)
    name = cluster["name"]
    k8s_version = cluster["version"]

    addon_name = "coredns"
    version_info = eks.describe_addon_versions(addonName=addon_name, kubernetesVersion=k8s_version)["addons"]
    if not version_info or not version_info[0]["addonVersions"]:
        raise AssertionError(f"no compatible {addon_name} addon version published for kubernetes {k8s_version}")
    addon_version = version_info[0]["addonVersions"][0]["addonVersion"]

    corefile = (
        ".:53 {\n"
        "    errors\n"
        "    health\n"
        '    ready # comment with "quotes" and a backslash \\ and unicode \u65e5\u672c\u8a9e\n'
        "    kubernetes cluster.local in-addr.arpa ip6.arpa {\n"
        "      pods insecure\n"
        "      fallthrough in-addr.arpa ip6.arpa\n"
        "    }\n"
        "    prometheus :9153\n"
        "    forward . /etc/resolv.conf\n"
        "    cache 30\n"
        "    loop\n"
        "    reload\n"
        "    loadbalance\n"
        "}\n"
    )
    config_values = {
        "replicaCount": 3,
        "resources": {
            "limits": {"cpu": "250m", "memory": "150Mi"},
            "requests": {"cpu": "100m", "memory": "70Mi"},
        },
        "corefile": corefile,
    }

    eks.create_addon(
        clusterName=name,
        addonName=addon_name,
        addonVersion=addon_version,
        configurationValues=json.dumps(config_values),
        resolveConflicts="OVERWRITE",
    )
    _wait_for_addon_settled(ctx, name, addon_name)

    described = eks.describe_addon(clusterName=name, addonName=addon_name)["addon"]
    persisted = json.loads(described["configurationValues"])
    assert persisted == config_values, f"configurationValues mutated on create: {persisted!r} != {config_values!r}"

    updated_values = dict(config_values)
    updated_values["replicaCount"] = 5
    updated_values["corefile"] = corefile + "# \u65e5\u672c\u8a9e\u30b3\u30e1\u30f3\u30c8 appended\n"
    update_resp = eks.update_addon(
        clusterName=name,
        addonName=addon_name,
        configurationValues=json.dumps(updated_values),
        resolveConflicts="OVERWRITE",
    )
    assert update_resp["update"]["status"] == "InProgress", update_resp["update"]
    # Both DescribeUpdate's terminal status and the addon's own ACTIVE/DEGRADED status wait on
    # the coredns Deployment rollout converging, which never happens on a cluster with no compute
    # for its pods to schedule on (confirmed against real AWS: both hang past 600s). The declared
    # configurationValues is stored independently of that rollout, so poll DescribeAddon directly
    # for the new value to appear rather than waiting on either status field.
    deadline = time.monotonic() + 60.0
    persisted_after = persisted
    while time.monotonic() < deadline:
        described_after = eks.describe_addon(clusterName=name, addonName=addon_name)["addon"]
        persisted_after = json.loads(described_after["configurationValues"])
        if persisted_after != persisted:
            break
        time.sleep(5)
    assert persisted_after == updated_values, (
        f"configurationValues mutated on update: {persisted_after!r} != {updated_values!r}"
    )
    assert persisted_after != persisted, (
        f"DescribeAddon returned the pre-update configurationValues snapshot after UpdateAddon settled: "
        f"{persisted_after!r}"
    )


def _get_two_az_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az: dict[str, str] = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            return list(by_az.values())[:3]

    vpc_id = ec2.create_vpc(CidrBlock="10.42.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-vpc-")}])
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ]
    ][:2]
    if len(azs) < 2:
        raise AssertionError("fewer than 2 availability zones available to provision EKS cluster subnets")
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.42.{i}.0/24", AvailabilityZone=az)["Subnet"][
            "SubnetId"
        ]
        ec2.create_tags(Resources=[subnet_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-subnet-")}])
        ctx.on_cleanup(lambda sid=subnet_id: ec2.delete_subnet(SubnetId=sid))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _create_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    for _ in range(10):
        try:
            iam.get_role(RoleName=role_name)
            break
        except Exception:
            time.sleep(2)
    return role["Arn"]


def _wait_for_cluster_active(ctx, name, timeout_s=1200.0, interval_s=20.0):
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cluster = eks.describe_cluster(name=name)["cluster"]
        status = cluster["status"]
        if status == "ACTIVE":
            return cluster
        if status == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED status while waiting for ACTIVE")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} did not reach ACTIVE within {timeout_s}s")


def _delete_cluster_safe(ctx, name):
    eks = ctx.client("eks")
    deadline = time.monotonic() + 300.0
    while time.monotonic() < deadline:
        try:
            status = eks.describe_cluster(name=name)["cluster"]["status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        if status not in ("CREATING", "UPDATING", "DELETING"):
            break
        time.sleep(15)
    _delete_eks_cluster_retrying(eks, name)
    gone_deadline = time.monotonic() + 600.0
    while time.monotonic() < gone_deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        time.sleep(15)


def _create_active_cluster(ctx, **extra_kwargs):
    eks = ctx.client("eks")
    subnets = _get_two_az_subnets(ctx)
    role_arn = _create_cluster_role(ctx)
    name = ctx.unique_name("sim2real-eks-")
    kwargs = dict(name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnets})
    kwargs.update(extra_kwargs)
    deadline = time.monotonic() + 90.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(**kwargs)
            break
        except Exception as exc:  # freshly-created IAM role can take a few seconds to propagate
            last_exc = exc
            time.sleep(5)
    else:
        raise last_exc
    ctx.on_cleanup(lambda: _delete_cluster_safe(ctx, name))
    return _wait_for_cluster_active(ctx, name)


def _wait_for_addon_settled(ctx, cluster_name, addon_name, timeout_s=600.0, interval_s=15.0):
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        addon = eks.describe_addon(clusterName=cluster_name, addonName=addon_name)["addon"]
        status = addon["status"]
        if status in ("ACTIVE", "DEGRADED"):
            return addon
        if status in ("CREATE_FAILED", "UPDATE_FAILED"):
            raise AssertionError(f"addon {addon_name} entered {status}")
        time.sleep(interval_s)
    raise AssertionError(f"addon {addon_name} did not settle within {timeout_s}s")



def _delete_eks_cluster_retrying(eks, name, timeout_s=900.0, interval_s=20.0):
    """DeleteCluster, retried while EKS refuses it because an update or child resource is in flight."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return eks.delete_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return None
            if e.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
