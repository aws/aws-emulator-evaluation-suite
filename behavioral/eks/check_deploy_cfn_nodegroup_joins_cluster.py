"""deploy-cfn-nodegroup-joins-cluster."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-cfn-nodegroup-joins-cluster"
GROUP = "deploy"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed AWS::EKS::Nodegroup transitions to ACTIVE and is attached
    to and visible under its parent cluster through the EKS API."""
    cfn = ctx.client("cloudformation")
    eks = ctx.client("eks")

    cluster_name = ctx.unique_name("sim2real-eks-cfn-")
    nodegroup_name = ctx.unique_name("sim2real-eks-ng-")
    template = f"""
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.61.0.0/16
      Tags:
        - Key: sim2real:managed
          Value: "true"
  Igw:
    Type: AWS::EC2::InternetGateway
  IgwAttach:
    Type: AWS::EC2::VPCGatewayAttachment
    Properties:
      VpcId: !Ref Vpc
      InternetGatewayId: !Ref Igw
  SubnetA:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.61.0.0/24
      AvailabilityZone: !Select [0, !GetAZs '']
      MapPublicIpOnLaunch: true
  SubnetB:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.61.1.0/24
      AvailabilityZone: !Select [1, !GetAZs '']
      MapPublicIpOnLaunch: true
  RouteTable:
    Type: AWS::EC2::RouteTable
    Properties:
      VpcId: !Ref Vpc
  Route:
    Type: AWS::EC2::Route
    DependsOn: IgwAttach
    Properties:
      RouteTableId: !Ref RouteTable
      DestinationCidrBlock: 0.0.0.0/0
      GatewayId: !Ref Igw
  AssocA:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties:
      SubnetId: !Ref SubnetA
      RouteTableId: !Ref RouteTable
  AssocB:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties:
      SubnetId: !Ref SubnetB
      RouteTableId: !Ref RouteTable
  ClusterRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: eks.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/AmazonEKSClusterPolicy
      Tags:
        - Key: sim2real:managed
          Value: "true"
  NodeRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy
        - arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy
        - arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly
      Tags:
        - Key: sim2real:managed
          Value: "true"
  Cluster:
    Type: AWS::EKS::Cluster
    Properties:
      Name: {cluster_name}
      RoleArn: !GetAtt ClusterRole.Arn
      ResourcesVpcConfig:
        SubnetIds:
          - !Ref SubnetA
          - !Ref SubnetB
  Nodegroup:
    Type: AWS::EKS::Nodegroup
    Properties:
      ClusterName: !Ref Cluster
      NodegroupName: {nodegroup_name}
      NodeRole: !GetAtt NodeRole.Arn
      Subnets:
        - !Ref SubnetA
        - !Ref SubnetB
      ScalingConfig:
        MinSize: 1
        MaxSize: 1
        DesiredSize: 1
      InstanceTypes:
        - t3.medium
      AmiType: AL2023_x86_64_STANDARD
"""

    stack_name = ctx.unique_name("sim2real-eks-stack-")
    cfn.create_stack(
        StackName=stack_name, TemplateBody=template, Capabilities=["CAPABILITY_IAM"]
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_name))
    _wait_stack_status(cfn, stack_name, "CREATE_COMPLETE", timeout_s=1800.0)

    # Verify through the EKS API: the nodegroup is ACTIVE and attached to the cluster.
    ng = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)["nodegroup"]
    assert ng["status"] == "ACTIVE", f"unexpected nodegroup status {ng['status']}"
    assert ng["clusterName"] == cluster_name, f"expected clusterName {cluster_name}, got {ng['clusterName']}"

    listed = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"clusterName": cluster_name}
        if token:
            kwargs["nextToken"] = token
        resp = eks.list_nodegroups(**kwargs)
        listed.extend(resp.get("nodegroups", []))
        token = resp.get("nextToken")
        if not token:
            break
    assert nodegroup_name in listed, f"{nodegroup_name} not present under cluster {cluster_name}"

    cluster = eks.describe_cluster(name=cluster_name)["cluster"]
    assert cluster["status"] == "ACTIVE", f"expected cluster {cluster_name} ACTIVE, got {cluster['status']}"


def _wait_stack_status(cfn: Any, stack_name: str, want: str, timeout_s: float = 1800.0, interval_s: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        status = desc["StackStatus"]
        if status == want:
            return
        if status.endswith("FAILED") or status.endswith("ROLLBACK_COMPLETE"):
            events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
            all_events = [
                f"{e['LogicalResourceId']}={e['ResourceStatus']}: {e.get('ResourceStatusReason')}"
                for e in events
            ]
            raise AssertionError(
                f"stack {stack_name} entered {status}: {desc.get('StackStatusReason')}; events: {all_events}"
            )
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach {want} in {timeout_s}s (last={status})")


def _delete_stack_and_wait(cfn: Any, stack_name: str, timeout_s: float = 1800.0, interval_s: float = 20.0) -> None:
    from botocore.exceptions import ClientError

    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        except ClientError as err:
            if err.response["Error"]["Code"] in ("ValidationError",):
                return
            raise
        status = desc["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} DELETE_FAILED: {desc.get('StackStatusReason')}")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not delete within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
