"""deploy-msk-serverless-cfn-topic-createable."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-msk-serverless-cfn-topic-createable"
GROUP = "deploy"
SERVICES = ["kafka"]

# MSK's refusal for any Topic Management API call against a serverless cluster.
_TOPIC_API_REFUSAL = "Topic APIs are not supported on serverless clusters."

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  ClusterName:
    Type: String
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.79.0.0/16
      EnableDnsSupport: true
      EnableDnsHostnames: true
      Tags: [{Key: Name, Value: !Ref ClusterName}]
  SubnetA:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.79.0.0/24
      AvailabilityZone: !Select [0, !GetAZs '']
  SubnetB:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.79.1.0/24
      AvailabilityZone: !Select [1, !GetAZs '']
  ClusterSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: sim2real msk serverless cfn sg
      VpcId: !Ref Vpc
  ServerlessCluster:
    Type: AWS::MSK::ServerlessCluster
    Properties:
      ClusterName: !Ref ClusterName
      ClientAuthentication:
        Sasl:
          Iam:
            Enabled: true
      VpcConfigs:
        - SubnetIds: [!Ref SubnetA, !Ref SubnetB]
          SecurityGroups: [!Ref ClusterSG]
Outputs:
  ClusterArn:
    Value: !Ref ServerlessCluster
"""


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed MSK Serverless cluster reaches ACTIVE, but CreateTopic and
    DescribeTopic on it fail ServerlessUnsupportedException: serverless topics are created
    only through the Kafka protocol."""
    from botocore.exceptions import ClientError

    kafka = ctx.client("kafka")
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-kafka-svls")
    stack_name = ctx.unique_name("sim2real-kafka-svls-stack-")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[{"ParameterKey": "ClusterName", "ParameterValue": name}],
        Capabilities=["CAPABILITY_IAM"],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))

    outputs = _wait_stack(ctx, stack_name, "CREATE_COMPLETE", timeout_s=1800.0)
    cluster_arn = outputs["ClusterArn"]

    info = _wait_cluster_state(ctx, kafka, cluster_arn, {"ACTIVE"}, timeout_s=1200.0)
    assert info["State"] == "ACTIVE", f"expected cluster State=ACTIVE, got {info['State']!r}"
    assert info["ClusterType"] == "SERVERLESS", (
        f"expected ClusterType=SERVERLESS, got {info['ClusterType']!r}"
    )

    topic_name = ctx.unique_name("sim2real-topic-")
    try:
        kafka.create_topic(
            ClusterArn=cluster_arn, TopicName=topic_name, PartitionCount=1, ReplicationFactor=3
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ServerlessUnsupportedException", (
            f"expected CreateTopic on a serverless cluster to be refused with "
            f"ServerlessUnsupportedException, got {code!r}: {e}"
        )
        message = e.response["Error"].get("Message")
        assert message == _TOPIC_API_REFUSAL, f"unexpected CreateTopic message: {message!r}"
    else:
        raise AssertionError(
            f"CreateTopic unexpectedly succeeded against serverless cluster {cluster_arn} "
            "-- MSK Serverless does not support the Topic Management API"
        )

    # Independent read at the destination, through a different operation than the one
    # that attempted the mutation: the topic was never created, and the control-plane
    # read for it is refused the same deterministic way, not merely "not found".
    try:
        kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ServerlessUnsupportedException", (
            f"expected DescribeTopic on a serverless cluster to be refused with "
            f"ServerlessUnsupportedException, got {code!r}: {e}"
        )
        message = e.response["Error"].get("Message")
        assert message == _TOPIC_API_REFUSAL, f"unexpected DescribeTopic message: {message!r}"
    else:
        raise AssertionError(f"DescribeTopic unexpectedly succeeded for {topic_name!r}")


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
                for e in cfn.describe_stack_events(StackName=stack_name)["StackEvents"][:50]:
                    if e.get("ResourceStatus", "").endswith("FAILED"):
                        events.append(
                            f"{e.get('LogicalResourceId')} [{e.get('ResourceType')}]: {e.get('ResourceStatusReason')}"
                        )
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
        info = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]
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
