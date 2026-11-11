"""create-nodegroup-disk-size-out-of-range-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-nodegroup-disk-size-out-of-range-rejected"
GROUP = "negative-classes"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateNodegroup with diskSize outside the permitted range is rejected with
    InvalidParameterException, leaving no node group behind, while a well-formed
    node group creation call on the same cluster is accepted."""
    eks = ctx.client("eks")
    role_arn = _create_cluster_role(ctx)
    node_role_arn = _create_node_role(ctx)
    subnet_ids = _get_subnets(ctx)
    cluster_name, _cluster = _create_active_cluster(ctx, role_arn, subnet_ids)

    bad_nodegroup_name = ctx.unique_name("sim2real-ng-bad-")
    code, message = _error(
        lambda: eks.create_nodegroup(
            clusterName=cluster_name,
            nodegroupName=bad_nodegroup_name,
            subnets=subnet_ids,
            nodeRole=node_role_arn,
            diskSize=-1,
            scalingConfig={"minSize": 1, "maxSize": 1, "desiredSize": 1},
            tags={"sim2real": "1"},
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == "diskSize must be > 0", message

    # effect absent: the bad node group was never created
    names = eks.list_nodegroups(clusterName=cluster_name)["nodegroups"]
    assert bad_nodegroup_name not in names, (
        f"nodegroup {bad_nodegroup_name!r} rejected for out-of-range diskSize must not exist, "
        f"but list_nodegroups returned {names!r}"
    )

    # positive control: a well-formed CreateNodegroup call on the same cluster is accepted
    good_nodegroup_name = ctx.unique_name("sim2real-ng-good-")
    resp = eks.create_nodegroup(
        clusterName=cluster_name,
        nodegroupName=good_nodegroup_name,
        subnets=subnet_ids,
        nodeRole=node_role_arn,
        diskSize=20,
        instanceTypes=["t3.small"],
        scalingConfig={"minSize": 1, "maxSize": 1, "desiredSize": 1},
        tags={"sim2real": "1"},
    )
    ctx.on_cleanup(lambda: eks.delete_nodegroup(clusterName=cluster_name, nodegroupName=good_nodegroup_name))
    assert resp["nodegroup"]["status"] in ("CREATING", "ACTIVE"), (
        f"expected CreateNodegroup with in-range diskSize to accept, got status {resp['nodegroup']['status']!r}"
    )
    good_names = eks.list_nodegroups(clusterName=cluster_name)["nodegroups"]
    assert good_nodegroup_name in good_names, (
        f"expected {good_nodegroup_name!r} in list_nodegroups after a well-formed CreateNodegroup, "
        f"got {good_names!r}"
    )


# ===== helpers =====
_EKS_CLUSTER_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
}
_EC2_NODE_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
}


def _error(fn):
    """The (code, message) fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_cluster_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-eks-role-")
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_EKS_CLUSTER_TRUST),
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)

    def _cleanup():
        iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn)
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _create_node_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-eks-node-role-")
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_EC2_NODE_TRUST),
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]
    policy_arns = [
        "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
        "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
        "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    ]
    for arn in policy_arns:
        iam.attach_role_policy(RoleName=name, PolicyArn=arn)

    def _cleanup():
        for arn in policy_arns:
            iam.detach_role_policy(RoleName=name, PolicyArn=arn)
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _get_subnets(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    assert len(subnet_ids) >= 2, f"need >=2 AZ-distinct subnets in vpc {vpc_id}, found {subnet_ids}"
    return subnet_ids[:3]


def _poll_until(probe, predicate, timeout_s, interval_s=20):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed={last!r}")


def _create_active_cluster(ctx, role_arn: str, subnet_ids: list[str]):
    eks = ctx.client("eks")
    name = ctx.unique_name("sim2real-eks-cl-")
    # A brand-new IAM role is rejected with InvalidParameterException until it propagates.
    deadline = time.monotonic() + 60.0
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + max(1.0, left - 5.0))
    while True:
        try:
            eks.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                tags={"sim2real": "1"},
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidParameterException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(eks, name, timeout_s=1800.0))
    cluster = _poll_until(
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "FAILED"),
        timeout_s=1200,
        interval_s=20,
    )
    if cluster["status"] != "ACTIVE":
        raise AssertionError(f"cluster failed to become ACTIVE: {cluster}")
    return name, cluster


def _delete_eks_cluster_and_wait(eks, name, timeout_s=1200.0, interval_s=20.0):
    """Delete an EKS cluster and wait until it is gone, so its ENIs leave the network.

    DeleteCluster is refused while an update, node group or add-on operation still runs; that
    ResourceInUseException is retried until the deadline.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            eks.delete_cluster(name=name)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"EKS cluster {name} still exists {timeout_s:.0f}s after DeleteCluster")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
