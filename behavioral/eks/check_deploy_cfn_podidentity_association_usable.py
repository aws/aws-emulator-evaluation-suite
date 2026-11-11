"""deploy-cfn-podidentity-association-usable."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-podidentity-association-usable"
GROUP = "deploy"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed AWS::EKS::PodIdentityAssociation is immediately usable:
    describing it returns the bound role and it is enumerable by namespace/service account."""
    cfn = ctx.client("cloudformation")
    eks = ctx.client("eks")

    cluster_name = ctx.unique_name("sim2real-eks-cfn-")
    namespace = "default"
    service_account = ctx.unique_name("sim2real-sa-")[:63]
    template = f"""
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.62.0.0/16
  SubnetA:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.62.0.0/24
      AvailabilityZone: !Select [0, !GetAZs '']
  SubnetB:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.62.1.0/24
      AvailabilityZone: !Select [1, !GetAZs '']
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
  PodRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: pods.eks.amazonaws.com
            Action:
              - sts:AssumeRole
              - sts:TagSession
  Cluster:
    Type: AWS::EKS::Cluster
    Properties:
      Name: {cluster_name}
      RoleArn: !GetAtt ClusterRole.Arn
      ResourcesVpcConfig:
        SubnetIds:
          - !Ref SubnetA
          - !Ref SubnetB
  PodIdentityAssociation:
    Type: AWS::EKS::PodIdentityAssociation
    Properties:
      ClusterName: !Ref Cluster
      Namespace: {namespace}
      ServiceAccount: {service_account}
      RoleArn: !GetAtt PodRole.Arn
Outputs:
  AssociationId:
    Value: !GetAtt PodIdentityAssociation.AssociationId
  RoleArn:
    Value: !GetAtt PodRole.Arn
"""

    stack_name = ctx.unique_name("sim2real-eks-stack-")
    cfn.create_stack(
        StackName=stack_name, TemplateBody=template, Capabilities=["CAPABILITY_IAM"]
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_name))
    _wait_stack_status(cfn, stack_name, "CREATE_COMPLETE", timeout_s=1500.0)

    outputs = {o["OutputKey"]: o["OutputValue"] for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]}
    association_id = outputs["AssociationId"]
    role_arn = outputs["RoleArn"]

    described = eks.describe_pod_identity_association(
        clusterName=cluster_name, associationId=association_id
    )["association"]
    assert described["roleArn"] == role_arn, f"expected roleArn {role_arn!r}, got {described['roleArn']!r}"
    assert described["namespace"] == namespace, (
        f"expected namespace {namespace!r}, got {described['namespace']!r}"
    )
    assert described["serviceAccount"] == service_account, (
        f"expected serviceAccount {service_account!r}, got {described['serviceAccount']!r}"
    )

    listed = eks.list_pod_identity_associations(
        clusterName=cluster_name, namespace=namespace, serviceAccount=service_account
    )["associations"]
    assert any(a["associationId"] == association_id for a in listed), (
        "association not enumerable by namespace/serviceAccount"
    )

    # Teardown is already mandatory (ctx.on_cleanup below); make it a free negative too:
    # the association must stop being describable once the stack that created it is gone.
    _delete_stack_and_wait(cfn, stack_name)
    try:
        eks.describe_pod_identity_association(clusterName=cluster_name, associationId=association_id)
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException after stack deletion, got {code}"
        )
        message = err.response["Error"].get("Message", "")
        # The stack owns the cluster too, so the lookup fails on the cluster first.
        assert message == f"No cluster found for name: {cluster_name}.", message
    else:
        raise AssertionError("pod identity association still describable after its stack was deleted")


# ===== helpers =====
def _wait_stack_status(cfn: Any, stack_name: str, want: str, timeout_s: float = 1500.0, interval_s: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        status = desc["StackStatus"]
        if status == want:
            return
        if status.endswith("FAILED") or status.endswith("ROLLBACK_COMPLETE"):
            raise AssertionError(f"stack {stack_name} entered {status}: {desc.get('StackStatusReason')}")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach {want} in {timeout_s}s (last={status})")


def _delete_stack_and_wait(cfn: Any, stack_name: str, timeout_s: float = 1500.0, interval_s: float = 20.0) -> None:
    # DeleteStack on an already-deleted stack succeeds, so any error here is a real failure.
    cfn.delete_stack(StackName=stack_name)
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
