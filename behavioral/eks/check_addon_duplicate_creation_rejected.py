"""addon-duplicate-creation-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "addon-duplicate-creation-rejected"
GROUP = "state-machine"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating an addon that already exists on the cluster is rejected, and the original addon is left untouched."""
    eks = ctx.client("eks")
    cluster = _create_active_cluster(ctx)
    name = cluster["name"]
    addon_name = "eks-pod-identity-agent"

    # Positive control: the first create must succeed.
    created = eks.create_addon(clusterName=name, addonName=addon_name)["addon"]
    original_arn = created["addonArn"]
    settled = _wait_for_addon_settled(ctx, name, addon_name)
    assert settled["status"] in ("ACTIVE", "DEGRADED"), f"expected ACTIVE or DEGRADED, got {settled['status']!r}"

    # Break exactly one thing: create the same addon a second time.
    code = _expect_error(lambda: eks.create_addon(clusterName=name, addonName=addon_name))
    assert code == ("ResourceInUseException", "Addon already exists."), f"expected ResourceInUseException, got {code!r}"

    # Effect absent: exactly one addon of this name still exists, unchanged.
    listed = eks.list_addons(clusterName=name)["addons"]
    assert listed.count(addon_name) == 1, f"expected exactly one {addon_name} addon, found {listed!r}"
    described_after = eks.describe_addon(clusterName=name, addonName=addon_name)["addon"]
    assert described_after["addonArn"] == original_arn, "addon ARN must not change after a rejected duplicate create"


def _expect_error(fn):
    """Call fn(); return its ClientError (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _get_two_az_subnets(ctx):
    """Adopt the shared network's subnets if usable; otherwise provision a throwaway VPC (no ambient dependency)."""
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
        raise AssertionError("region does not have >=2 available availability zones for an EKS cluster")
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


def _create_cluster_with_role_propagation_retry(eks, timeout_s=120.0, interval_s=10.0, **kwargs):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            eks.create_cluster(**kwargs)
            return
        except ClientError as exc:  # a just-created IAM role can take a few seconds to propagate to EKS
            code = exc.response["Error"]["Code"]
            if code != "InvalidParameterException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_active_cluster(ctx, **extra_kwargs):
    eks = ctx.client("eks")
    subnets = _get_two_az_subnets(ctx)
    role_arn = _create_cluster_role(ctx)
    name = ctx.unique_name("sim2real-eks-")
    kwargs = dict(name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnets})
    kwargs.update(extra_kwargs)
    _create_cluster_with_role_propagation_retry(eks, **kwargs)
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
