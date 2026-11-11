"""deploy-msk-cluster-cfn-bootstrap-brokers-reachable."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-msk-cluster-cfn-bootstrap-brokers-reachable"
GROUP = "deploy"
SERVICES = ["kafka"]

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  ClusterName:
    Type: String
  KafkaVersion:
    Type: String
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.78.0.0/16
      Tags: [{Key: Name, Value: !Ref ClusterName}, {Key: "sim2real:managed", Value: "true"}]
  SubnetA:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.78.0.0/24
      AvailabilityZone: !Select [0, !GetAZs '']
      Tags: [{Key: "sim2real:managed", Value: "true"}]
  SubnetB:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.78.1.0/24
      AvailabilityZone: !Select [1, !GetAZs '']
      Tags: [{Key: "sim2real:managed", Value: "true"}]
  ClusterSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: sim2real msk cfn sg
      VpcId: !Ref Vpc
      Tags: [{Key: "sim2real:managed", Value: "true"}]
  MskCluster:
    Type: AWS::MSK::Cluster
    Properties:
      ClusterName: !Ref ClusterName
      KafkaVersion: !Ref KafkaVersion
      NumberOfBrokerNodes: 2
      BrokerNodeGroupInfo:
        InstanceType: kafka.t3.small
        ClientSubnets: [!Ref SubnetA, !Ref SubnetB]
        SecurityGroups: [!Ref ClusterSG]
        StorageInfo:
          EBSStorageInfo:
            VolumeSize: 100
      Tags: {"sim2real:managed": "true"}
Outputs:
  ClusterArn:
    Value: !Ref MskCluster
"""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A cluster deployed via CloudFormation reaches ACTIVE and its broker/node
    endpoints reflect the 2-broker count declared in the template."""
    kafka = ctx.client("kafka")
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-kafka-cfn-")

    versions = kafka.list_kafka_versions().get("KafkaVersions", [])
    active = [v for v in versions if v.get("Status", "ACTIVE") == "ACTIVE"]
    kafka_version = (active or versions)[0]["Version"]

    stack_name = ctx.unique_name("sim2real-behav-kafka-cfn-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[
            {"ParameterKey": "ClusterName", "ParameterValue": name},
            {"ParameterKey": "KafkaVersion", "ParameterValue": kafka_version},
        ],
        Capabilities=["CAPABILITY_IAM"],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))

    outputs = _wait_stack(ctx, stack_name, "CREATE_COMPLETE", timeout_s=2400.0)
    cluster_arn = outputs["ClusterArn"]

    info = _wait_cluster_state(ctx, kafka, cluster_arn, {"ACTIVE"}, timeout_s=1800.0)
    assert info["State"] == "ACTIVE"
    assert info["NumberOfBrokerNodes"] == 2

    brokers = kafka.get_bootstrap_brokers(ClusterArn=cluster_arn)
    broker_string = brokers.get("BootstrapBrokerString") or brokers.get("BootstrapBrokerStringTls")
    assert broker_string, "expected a plaintext or TLS bootstrap broker string"
    endpoints = [e for e in broker_string.split(",") if e]
    assert len(endpoints) == 2, f"expected 2 bootstrap broker endpoints, got {len(endpoints)}"

    nodes = kafka.list_nodes(ClusterArn=cluster_arn)["NodeInfoList"]
    assert len(nodes) == 2, f"expected 2 nodes from ListNodes, got {len(nodes)}"


def _stack_outputs(cfn, stack_name: str) -> dict[str, str]:
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_stack(ctx, stack_name: str, target_status: str, timeout_s: float = 1800.0) -> dict[str, str]:
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        status = stack["StackStatus"]
        last = status
        if status == target_status:
            return _stack_outputs(cfn, stack_name)
        if status.endswith("FAILED") or status == "ROLLBACK_COMPLETE":
            reason = stack.get("StackStatusReason", "")
            events = []
            try:
                for e in cfn.describe_stack_events(StackName=stack_name)["StackEvents"][:10]:
                    if "FAILED" in e.get("ResourceStatus", ""):
                        events.append(f"{e.get('LogicalResourceId')}: {e.get('ResourceStatusReason')}")
            except Exception:
                pass
            raise AssertionError(
                f"stack {stack_name} entered {status}: {reason}; failed resources: {events}"
            )
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"stack {stack_name} reaching {target_status}: the run budget ended first; not graded")
    raise AssertionError(f"stack {stack_name} never reached {target_status} (last={last})")


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + 1800.0
    while time.monotonic() < deadline:
        try:
            stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return
        if stack["StackStatus"] == "DELETE_COMPLETE":
            return
        time.sleep(2.0)


def _wait_cluster_state(ctx, kafka, cluster_arn: str, target_states: set, timeout_s: float = 1800.0) -> dict:
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]
        state = info["State"]
        last = state
        if state in target_states:
            return info
        if state == "FAILED":
            raise AssertionError(f"cluster entered FAILED: {info.get('StateInfo')}")
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {cluster_arn} reaching {target_states}: the run budget ended first; not graded")
    raise AssertionError(f"cluster never reached {target_states} (last={last})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
