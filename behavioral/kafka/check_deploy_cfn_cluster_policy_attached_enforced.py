"""deploy-cfn-cluster-policy-attached-enforced."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "deploy-cfn-cluster-policy-attached-enforced"
GROUP = "server-side"
SERVICES = ["kafka"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  ClusterName: {Type: String}
  SubnetId1: {Type: String}
  SubnetId2: {Type: String}
  SecurityGroupId: {Type: String}
  KafkaVersion: {Type: String}
Resources:
  MskCluster:
    Type: AWS::MSK::Cluster
    Properties:
      ClusterName: !Ref ClusterName
      KafkaVersion: !Ref KafkaVersion
      NumberOfBrokerNodes: 2
      BrokerNodeGroupInfo:
        InstanceType: kafka.t3.small
        ClientSubnets: [!Ref SubnetId1, !Ref SubnetId2]
        SecurityGroups: [!Ref SecurityGroupId]
      Tags: {Name: !Ref ClusterName}
  MskClusterPolicy:
    Type: AWS::MSK::ClusterPolicy
    Properties:
      ClusterArn: !Ref MskCluster
      Policy:
        Version: "2012-10-17"
        Statement:
          - Sid: AllowSameAccountDescribe
            Effect: Allow
            Principal:
              AWS: !Sub "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"
            Action: "kafka:DescribeClusterV2"
            Resource: !Ref MskCluster
Outputs:
  ClusterArn:
    Value: !Ref MskCluster
"""


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A resource policy attached to a cluster at CloudFormation deploy time (AWS::MSK::ClusterPolicy)
    is retrievable via GetClusterPolicy with the exact statement content, and PutClusterPolicy
    applied post-hoc to the same cluster produces an identically-shaped, versioned result."""
    subnet_ids, sg_id = _default_subnets_and_sg(ctx, count=2)
    kafka_version = _pick_kafka_version(ctx)
    cfn = ctx.client("cloudformation")
    kafka = ctx.client("kafka")
    stack_name = ctx.unique_name("sim2real-msk-pol-cfn-")
    cluster_name = ctx.unique_name("sim2real-msk-pol-")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[
            {"ParameterKey": "ClusterName", "ParameterValue": cluster_name},
            {"ParameterKey": "SubnetId1", "ParameterValue": subnet_ids[0]},
            {"ParameterKey": "SubnetId2", "ParameterValue": subnet_ids[1]},
            {"ParameterKey": "SecurityGroupId", "ParameterValue": sg_id},
            {"ParameterKey": "KafkaVersion", "ParameterValue": kafka_version},
        ],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    try:
        cfn.get_waiter("stack_create_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 3000}
        )
    except Exception as exc:  # surface the real CFN failure reason
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
        reasons = [
            f"{e.get('LogicalResourceId')}: {e.get('ResourceStatus')} - {e.get('ResourceStatusReason')}"
            for e in events
            if e.get("ResourceStatusReason")
        ]
        raise AssertionError(f"stack {stack_name} failed to create: {reasons}") from exc

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    }
    cluster_arn = outputs["ClusterArn"]

    # The policy attached at deploy time must be retrievable and match what we declared.
    cfn_policy_resp = kafka.get_cluster_policy(ClusterArn=cluster_arn)
    cfn_policy = json.loads(cfn_policy_resp["Policy"])
    cfn_version = cfn_policy_resp["CurrentVersion"]
    statements = {s["Sid"]: s for s in cfn_policy["Statement"]}
    assert "AllowSameAccountDescribe" in statements, (
        f"CFN-attached cluster policy missing expected statement: {cfn_policy}"
    )
    stmt = statements["AllowSameAccountDescribe"]
    assert stmt["Action"] == "kafka:DescribeClusterV2", f"expected Action kafka:DescribeClusterV2, got {stmt['Action']}"
    assert stmt["Resource"] == cluster_arn, f"expected Resource {cluster_arn}, got {stmt['Resource']}"

    # Now attach an updated policy post-hoc via PutClusterPolicy on the SAME cluster and
    # confirm it is retrievable through the identical GetClusterPolicy contract: same field
    # names, a distinct incremented CurrentVersion, and the exact new statement content.
    updated_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowSameAccountDescribe",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{_account_id(ctx)}:root"},
                "Action": "kafka:DescribeClusterV2",
                "Resource": cluster_arn,
            },
            {
                "Sid": "PostHocAddedStatement",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{_account_id(ctx)}:root"},
                "Action": "kafka:GetBootstrapBrokers",
                "Resource": cluster_arn,
            },
        ],
    }
    put_resp = kafka.put_cluster_policy(
        ClusterArn=cluster_arn, Policy=json.dumps(updated_policy), CurrentVersion=cfn_version
    )
    assert put_resp["CurrentVersion"] != cfn_version, (
        "PutClusterPolicy did not advance CurrentVersion after modifying a CFN-attached policy"
    )

    # PutClusterPolicy's own response CurrentVersion is not the value a subsequent
    # GetClusterPolicy reports (observed reproducibly on real AWS across independent
    # clusters: the two calls return two different, stable version tokens for the same
    # write) -- so the terminal read is judged against the target's own state before the
    # write (cfn_version), not against the mutating call's self-reported value.
    post_hoc_resp = kafka.get_cluster_policy(ClusterArn=cluster_arn)
    post_hoc_policy = json.loads(post_hoc_resp["Policy"])
    post_hoc_statements = {s["Sid"]: s for s in post_hoc_policy["Statement"]}
    assert post_hoc_resp["CurrentVersion"] != cfn_version, (
        f"expected GetClusterPolicy CurrentVersion to advance past {cfn_version} after the "
        f"post-hoc update, got {post_hoc_resp['CurrentVersion']}"
    )
    assert "PostHocAddedStatement" in post_hoc_statements, (
        f"post-hoc PutClusterPolicy update was not reflected by GetClusterPolicy: {post_hoc_policy}"
    )
    assert post_hoc_statements["PostHocAddedStatement"]["Action"] == "kafka:GetBootstrapBrokers", (
        f"expected PostHocAddedStatement Action kafka:GetBootstrapBrokers, "
        f"got {post_hoc_statements['PostHocAddedStatement']['Action']}"
    )


# ===== helpers =====

def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _default_subnets_and_sg(ctx, count: int = 2):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region to place MSK broker ENIs")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())[:count]
    if len(subnet_ids) < count:
        raise AssertionError(f"shared network has fewer than {count} distinct AZs with subnets")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("no default security group found in the shared network")
    return subnet_ids, sgs[0]["GroupId"]


def _pick_kafka_version(ctx) -> str:
    # The newest ACTIVE version is not necessarily usable: MSK has started shipping
    # kraft-only versions (e.g. 4.2.x.kraft) that CreateCluster rejects for a Standard
    # broker instance type ("Standard instance types are not supported for Kafka
    # version 4.2.x.kraft"). The oldest ACTIVE version is the conservative choice that
    # stays compatible with Standard instance types.
    kafka = ctx.client("kafka")
    versions = kafka.list_kafka_versions().get("KafkaVersions", [])
    active = [v["Version"] for v in versions if v.get("Status") == "ACTIVE"]
    if "3.9.x" in active:  # recommended, still ZooKeeper; older Standard versions are refused
        return "3.9.x"
    candidates = active or [v["Version"] for v in versions]
    if not candidates:
        raise AssertionError("ListKafkaVersions returned no usable Kafka version")
    return sorted(candidates)[0]


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    # Bounded by the suite's 1800 s cleanup budget.
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 870}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
