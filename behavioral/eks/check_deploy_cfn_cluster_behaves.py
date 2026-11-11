"""deploy-cfn-cluster-behaves."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-cfn-cluster-behaves"
GROUP = "deploy"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed AWS::EKS::Cluster reaches ACTIVE and is independently
    describable/listable through the EKS API, not just CFN CREATE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    eks = ctx.client("eks")

    cluster_name = ctx.unique_name("sim2real-eks-cfn-")
    template = f"""
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.60.0.0/16
      Tags:
        - Key: sim2real
          Value: 'true'
  SubnetA:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.60.0.0/24
      AvailabilityZone: !Select [0, !GetAZs '']
      Tags:
        - Key: sim2real
          Value: 'true'
  SubnetB:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.60.1.0/24
      AvailabilityZone: !Select [1, !GetAZs '']
      Tags:
        - Key: sim2real
          Value: 'true'
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
        - Key: sim2real
          Value: 'true'
  Cluster:
    Type: AWS::EKS::Cluster
    Properties:
      Name: {cluster_name}
      RoleArn: !GetAtt ClusterRole.Arn
      ResourcesVpcConfig:
        SubnetIds:
          - !Ref SubnetA
          - !Ref SubnetB
Outputs:
  ClusterName:
    Value: !Ref Cluster
"""

    stack_name = ctx.unique_name("sim2real-eks-stack-")
    cfn.create_stack(
        StackName=stack_name, TemplateBody=template, Capabilities=["CAPABILITY_IAM"]
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_name, eks, cluster_name))
    _wait_stack_status(cfn, stack_name, "CREATE_COMPLETE", timeout_s=1500.0)

    # Independently verify through the EKS control plane, not the CFN status.
    described = eks.describe_cluster(name=cluster_name)["cluster"]
    assert described["status"] == "ACTIVE", f"unexpected status {described['status']}"
    assert described["name"] == cluster_name, (
        f"expected describe_cluster to report name {cluster_name!r}, got {described['name']!r}"
    )

    names = []
    token = None
    while True:
        kwargs = {"nextToken": token} if token else {}
        resp = eks.list_clusters(**kwargs)
        names.extend(resp.get("clusters", []))
        token = resp.get("nextToken")
        if not token:
            break
    assert cluster_name in names, f"{cluster_name} not present in ListClusters"


def _failure_reasons(cfn: Any, stack_name: str) -> list[str]:
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    return [
        f"{e['LogicalResourceId']} ({e['ResourceType']}) {e['ResourceStatus']}: {e.get('ResourceStatusReason')}"
        for e in events
    ]


def _wait_stack_status(cfn: Any, stack_name: str, want: str, timeout_s: float = 1500.0, interval_s: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        status = desc["StackStatus"]
        if status == want:
            return
        if status.endswith("FAILED") or status.endswith("ROLLBACK_COMPLETE"):
            reasons = _failure_reasons(cfn, stack_name)
            raise AssertionError(
                f"stack {stack_name} entered {status}: {desc.get('StackStatusReason')}; "
                f"resource failures: {reasons}"
            )
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach {want} in {timeout_s}s (last={status})")


def _delete_stack_and_wait(
    cfn: Any, stack_name: str, eks: Any, cluster_name: str, timeout_s: float = 1500.0, interval_s: float = 20.0
) -> None:
    from botocore.exceptions import ClientError

    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    deleted = False
    while time.monotonic() < deadline:
        try:
            desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        except ClientError as err:
            if err.response["Error"]["Code"] in ("ValidationError",):
                deleted = True
                break
            raise
        status = desc["StackStatus"]
        if status == "DELETE_COMPLETE":
            deleted = True
            break
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} DELETE_FAILED: {desc.get('StackStatusReason')}")
        time.sleep(interval_s)
    if not deleted:
        raise AssertionError(f"stack {stack_name} did not delete within {timeout_s}s")

    # The stack is gone; prove the cluster it owned is independently gone too, not just
    # absent from the CFN status word.
    try:
        eks.describe_cluster(name=cluster_name)
    except ClientError as err:
        code = err.response["Error"]["Code"]
        if code != "ResourceNotFoundException":
            raise AssertionError(
                f"describe_cluster({cluster_name}) after stack deletion raised {code}, "
                "expected ResourceNotFoundException"
            )
        message = err.response["Error"].get("Message")
        if (message or "").rstrip(".") != f"No cluster found for name: {cluster_name}":
            raise AssertionError(f"describe_cluster({cluster_name}) after stack deletion said {message!r}")
    else:
        raise AssertionError(
            f"describe_cluster({cluster_name}) still succeeded after the owning stack was deleted"
        )

    names: list[str] = []
    token = None
    while True:
        kwargs = {"nextToken": token} if token else {}
        resp = eks.list_clusters(**kwargs)
        names.extend(resp.get("clusters", []))
        token = resp.get("nextToken")
        if not token:
            break
    assert cluster_name not in names, f"{cluster_name} still present in ListClusters after stack deletion"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
