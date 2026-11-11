"""deploy-nodegroup-via-cloudformation-joins-cluster."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-nodegroup-via-cloudformation-joins-cluster"
GROUP = "deploy"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """An AWS::EKS::Nodegroup deployed via CloudFormation transitions to ACTIVE and
    is describable/enumerable against its parent cluster after stack completion."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    eks = ctx.client("eks")
    cfn = ctx.client("cloudformation")

    subnet_ids = _get_default_subnets(ctx, ec2, count=2)
    cluster_role_arn = _create_iam_role(
        ctx, iam, "eks.amazonaws.com", ["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"]
    )
    node_role_arn = _create_iam_role(
        ctx,
        iam,
        "ec2.amazonaws.com",
        [
            "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
            "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
            "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
        ],
    )

    cluster_name = ctx.unique_name("sim2real-eks-ng-")
    _create_cluster(ctx, eks, cluster_name, cluster_role_arn, subnet_ids)
    _wait_cluster_active(eks, cluster_name)

    nodegroup_name = ctx.unique_name("sim2real-ng-")
    stack_name = ctx.unique_name("sim2real-eks-ng-stack-")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Nodegroup": {
                "Type": "AWS::EKS::Nodegroup",
                "Properties": {
                    "ClusterName": cluster_name,
                    "NodegroupName": nodegroup_name,
                    "NodeRole": node_role_arn,
                    "Subnets": subnet_ids,
                    "ScalingConfig": {"MinSize": 1, "MaxSize": 1, "DesiredSize": 1},
                    "InstanceTypes": ["t3.medium"],
                },
            }
        },
    }

    def _delete_stack():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450}
        )

    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template))

    ctx.on_cleanup(_delete_stack)

    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1350}
    )

    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert stack["StackStatus"] == "CREATE_COMPLETE", f"unexpected stack status {stack['StackStatus']!r}"

    described = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)["nodegroup"]
    assert described["status"] == "ACTIVE", f"unexpected nodegroup status {described['status']!r}"

    # A CFN resource record alone would say ACTIVE too; the backing Auto Scaling group is the
    # EKS-reported evidence that CloudFormation actually drove the data plane.
    asgs = described.get("resources", {}).get("autoScalingGroups", [])
    assert len(asgs) >= 1, f"nodegroup {nodegroup_name} has no backing Auto Scaling group: {described.get('resources')}"

    names = eks.list_nodegroups(clusterName=cluster_name)["nodegroups"]
    assert nodegroup_name in names, f"{nodegroup_name} not present under cluster {cluster_name}: {names}"


# ===== helpers =====
def _get_default_subnets(ctx, ec2, count=2):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to provision an EKS cluster")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < count:
        raise AssertionError("shared network lacks enough AZ-distinct subnets for an EKS cluster")
    return subnet_ids[:count]


def _create_iam_role(ctx, iam, trust_service, managed_policy_arns):
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    for arn in managed_policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)

    def _cleanup():
        for arn in managed_policy_arns:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _create_cluster(ctx, eks, cluster_name, role_arn, subnet_ids):
    def _cleanup():
        eks.delete_cluster(name=cluster_name)
        _wait_cluster_deleted(eks, cluster_name)

    ctx.on_cleanup(_cleanup)
    deadline = time.monotonic() + 30
    last_err = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(
                name=cluster_name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
            )
            return
        except ClientError as exc:  # pragma: no cover - transient IAM propagation
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"CreateCluster never succeeded (role propagation?): {last_err}")


def _wait_cluster_active(eks, cluster_name):
    eks.get_waiter("cluster_active").wait(
        name=cluster_name, WaiterConfig={"Delay": 2, "MaxAttempts": 900}
    )


def _wait_cluster_deleted(eks, cluster_name):
    eks.get_waiter("cluster_deleted").wait(
        name=cluster_name, WaiterConfig={"Delay": 2, "MaxAttempts": 420}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
