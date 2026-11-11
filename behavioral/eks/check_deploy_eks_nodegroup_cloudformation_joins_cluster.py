"""deploy-eks-nodegroup-cloudformation-joins-cluster."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-eks-nodegroup-cloudformation-joins-cluster"
GROUP = "deploy"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A nodegroup deployed via CloudFormation reaches ACTIVE and registers as a real
    member of the target cluster (a backing Auto Scaling group), beyond stack completion."""
    vpc = _create_vpc_infra(ctx)
    cluster_role_arn = _create_cluster_role(ctx)
    node_role_arn = _create_node_role(ctx)

    cluster_name = ctx.unique_name("sim2real-eks-ngc-")
    _create_cluster_via_sdk(ctx, cluster_name, cluster_role_arn, vpc["subnet_ids"])

    nodegroup_name = ctx.unique_name("sim2real-eks-ng-")
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "ClusterName": {"Type": "String"},
            "NodegroupName": {"Type": "String"},
            "NodeRole": {"Type": "String"},
            "Subnets": {"Type": "List<AWS::EC2::Subnet::Id>"},
        },
        "Resources": {
            "EksNodegroup": {
                "Type": "AWS::EKS::Nodegroup",
                "Properties": {
                    "ClusterName": {"Ref": "ClusterName"},
                    "NodegroupName": {"Ref": "NodegroupName"},
                    "NodeRole": {"Ref": "NodeRole"},
                    "Subnets": {"Ref": "Subnets"},
                    "InstanceTypes": ["t3.medium"],
                    "AmiType": "AL2023_x86_64_STANDARD",
                    "ScalingConfig": {"MinSize": 1, "MaxSize": 2, "DesiredSize": 1},
                    "Tags": {"sim2real": CHECK},
                },
            }
        },
        "Outputs": {
            "NodegroupNameOut": {"Value": {"Fn::GetAtt": ["EksNodegroup", "NodegroupName"]}},
            "NodegroupArnOut": {"Value": {"Fn::GetAtt": ["EksNodegroup", "Arn"]}},
        },
    }
    result = _deploy_stack(
        ctx,
        template,
        {
            "ClusterName": cluster_name,
            "NodegroupName": nodegroup_name,
            "NodeRole": node_role_arn,
            "Subnets": ",".join(vpc["subnet_ids"]),
        },
        create_timeout_s=1200,
    )
    assert result["outputs"]["NodegroupNameOut"] == nodegroup_name, (
        f"stack output NodegroupNameOut is {result['outputs'].get('NodegroupNameOut')!r}, "
        f"expected {nodegroup_name!r}"
    )

    eks = ctx.client("eks")
    ng = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)["nodegroup"]
    assert ng["status"] == "ACTIVE", f"nodegroup status is {ng['status']!r}, not ACTIVE"
    assert ng["clusterName"] == cluster_name, (
        f"nodegroup reports clusterName {ng['clusterName']!r}, expected {cluster_name!r}"
    )

    # "Real member" of the cluster means EKS actually provisioned a backing Auto Scaling
    # group for it -- not just a stored CloudFormation resource record. A managed node
    # group is backed by exactly one Auto Scaling group (confirmed against real AWS).
    asgs = ng.get("resources", {}).get("autoScalingGroups", [])
    assert len(asgs) == 1, f"nodegroup has {len(asgs)} backing Auto Scaling groups, expected exactly 1"

    names = eks.list_nodegroups(clusterName=cluster_name)["nodegroups"]
    assert nodegroup_name in names, (
        f"{nodegroup_name!r} is not in ListNodegroups {names!r} for cluster {cluster_name!r}"
    )


# ===== helpers =====


def _retry_delete(fn, attempts: int = 12, delay_s: float = 10.0) -> None:
    last_exc = None
    for _ in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001 - best-effort cleanup retry
            last_exc = exc
            time.sleep(delay_s)
    if last_exc is not None:
        raise last_exc


def _create_vpc_infra(ctx) -> dict:
    ec2 = ctx.client("ec2")
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not default_vpcs:
        raise AssertionError("no shared network VPC available in this account/region for EKS subnets")
    vpc_id = default_vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    subnet_ids = sorted({s["SubnetId"] for s in subnets})[:3]
    if len(subnet_ids) < 2:
        raise AssertionError(
            f"shared network VPC {vpc_id} does not have enough shared-network subnets for EKS "
            f"(need >=2, found {len(subnet_ids)})"
        )
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": None}



def _create_cluster_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-cluster-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        finally:
            iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    return role_arn


def _create_node_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-node-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policies = [
        "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
        "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
        "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    ]

    def _cleanup():
        try:
            for p in policies:
                try:
                    iam.detach_role_policy(RoleName=role_name, PolicyArn=p)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "NoSuchEntity":
                        raise
        finally:
            iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    for p in policies:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=p)
    return role_arn


def _create_cluster_via_sdk(ctx, name: str, role_arn: str, subnet_ids: list[str]) -> None:
    eks = ctx.client("eks")
    deadline = time.monotonic() + 120.0
    while True:
        try:
            eks.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                tags={"sim2real": CHECK},
            )
            break
        except Exception as exc:  # noqa: BLE001 - retry only IAM-propagation style failures
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code == "InvalidParameterException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(ctx, name))
    _wait_cluster_status(ctx, name, "ACTIVE", timeout_s=1200)


def _wait_cluster_status(ctx, name: str, target: str, timeout_s: float = 1200.0, interval_s: float = 20.0) -> dict:
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        cluster = eks.describe_cluster(name=name)["cluster"]
        last_status = cluster["status"]
        if last_status == target:
            return cluster
        if last_status in ("FAILED",):
            raise AssertionError(f"cluster {name} entered terminal status {last_status}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} did not reach {target} within {timeout_s}s (last={last_status})")


def _delete_cluster_and_wait(ctx, name: str, timeout_s: float = 600.0, interval_s: float = 2.0) -> None:
    eks = ctx.client("eks")
    try:
        _delete_eks_cluster_retrying(eks, name)
    except Exception as exc:  # noqa: BLE001 - tolerate already-deleted during cleanup
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if code == "ResourceNotFoundException":
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} was not deleted within {timeout_s}s")


def _deploy_stack(ctx, template: dict, parameters: dict, create_timeout_s: float = 1500.0) -> dict:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-eks-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        waiter = cfn.get_waiter("stack_delete_complete")
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 360})

    ctx.on_cleanup(_cleanup)

    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": max(10, int(create_timeout_s // 2))})

    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    return {"stack_name": stack_name, "outputs": {o["OutputKey"]: o["OutputValue"] for o in outputs}}



def _delete_eks_cluster_retrying(eks, name, timeout_s=900.0, interval_s=20.0):
    """DeleteCluster, retried while EKS refuses it because an update or child resource is in flight."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return eks.delete_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
