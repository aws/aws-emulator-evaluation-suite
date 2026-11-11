"""deploy-msk-cluster-cfn-brokers-usable."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deploy-msk-cluster-cfn-brokers-usable"
GROUP = "deploy"
SERVICES = ["kafka"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed AWS::MSK::Cluster produces brokers that actually accept a
    topic creation and serve it back through DescribeTopic -- not merely
    CREATE_COMPLETE stack status."""
    kafka = ctx.client("kafka")
    _, subnets, sg = _default_vpc_and_subnets(ctx)
    version = _pick_kafka_version(ctx, kafka)
    cluster_name = ctx.unique_name("sim2real-behav-kafka-")

    template = _cfn_template()
    outputs = _deploy_cfn(
        ctx,
        template,
        {
            "ClusterName": cluster_name,
            "Subnet1": subnets[0],
            "Subnet2": subnets[1],
            "SecurityGroupId": sg,
            "KafkaVersion": version,
        },
        timeout_s=2400,
    )
    cluster_arn = outputs["ClusterArn"]

    info = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]
    assert info["State"] == "ACTIVE", f"expected cluster state ACTIVE after CREATE_COMPLETE, got {info['State']!r}"

    brokers = kafka.get_bootstrap_brokers(ClusterArn=cluster_arn)
    broker_string = brokers.get("BootstrapBrokerString") or brokers.get("BootstrapBrokerStringTls")
    assert broker_string, (
        f"no bootstrap brokers returned (neither plaintext nor TLS): {brokers!r}; a CFN "
        "MSK::Cluster with no explicit EncryptionInfo defaults ClientBroker to TLS-only, "
        "so BootstrapBrokerString alone is not a valid fidelity check for the default deploy"
    )

    topic_name = ctx.unique_name("sim2real-behav-topic-")
    kafka.create_topic(
        ClusterArn=cluster_arn,
        TopicName=topic_name,
        PartitionCount=1,
        ReplicationFactor=2,
    )
    topic = _wait_for_topic_active(ctx, kafka, cluster_arn, topic_name)
    assert topic["TopicName"] == topic_name, f"expected topic name {topic_name!r}, DescribeTopic returned {topic['TopicName']!r}"
    assert topic["PartitionCount"] == 1, f"expected 1 partition, DescribeTopic returned {topic['PartitionCount']!r}"
    assert topic["ReplicationFactor"] == 2, f"expected replication factor 2, DescribeTopic returned {topic['ReplicationFactor']!r}"


# ===== helpers =====


def _default_vpc_and_subnets(ctx, count=2):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to place MSK broker ENIs")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < count:
        raise AssertionError("shared network does not span enough AZs for an MSK cluster")
    sg = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]
    return vpc_id, list(by_az.values())[:count], sg


def _pick_kafka_version(ctx, kafka):
    versions = kafka.list_kafka_versions()["KafkaVersions"]
    active = [v["Version"] for v in versions if v.get("Status") == "ACTIVE"]
    if "3.9.x" in active:  # recommended, still ZooKeeper; older Standard versions are refused
        return "3.9.x"
    return (active or [v["Version"] for v in versions])[0]


def _wait_for_topic_active(ctx, kafka, cluster_arn, topic_name, timeout_s=180, interval_s=5):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name)
            last = resp.get("Status")
            if last == "ACTIVE":
                return resp
        except ClientError as e:
            if e.response["Error"]["Code"] != "NotFoundException":
                raise
        time.sleep(interval_s)
    raise AssertionError(f"topic {topic_name} did not become ACTIVE (last status={last})")


def _cfn_template() -> str:
    return """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  ClusterName:
    Type: String
  Subnet1:
    Type: String
  Subnet2:
    Type: String
  SecurityGroupId:
    Type: String
  KafkaVersion:
    Type: String
Resources:
  MSKCluster:
    Type: AWS::MSK::Cluster
    Properties:
      ClusterName: !Ref ClusterName
      KafkaVersion: !Ref KafkaVersion
      NumberOfBrokerNodes: 2
      BrokerNodeGroupInfo:
        InstanceType: kafka.t3.small
        ClientSubnets: [!Ref Subnet1, !Ref Subnet2]
        SecurityGroups: [!Ref SecurityGroupId]
        StorageInfo:
          EBSStorageInfo:
            VolumeSize: 10
Outputs:
  ClusterArn:
    Value: !Ref MSKCluster
""".strip()


def _deploy_cfn(ctx, template_body, parameters, timeout_s=2400):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-kafka-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
        Capabilities=["CAPABILITY_IAM"],
    )

    def _delete_stack():
        # The waiter raises on DELETE_FAILED; 2 s x 870 fits the suite's 1800 s cleanup budget.
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 870})

    ctx.on_cleanup(_delete_stack)
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        status = stacks[0]["StackStatus"]
        if status == "CREATE_COMPLETE":
            return {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])}
        if "ROLLBACK" in status or status == "CREATE_FAILED":
            events = []
            try:
                for e in cfn.describe_stack_events(StackName=stack_name)["StackEvents"][:15]:
                    if "FAILED" in e.get("ResourceStatus", ""):
                        events.append(f"{e.get('LogicalResourceId')}: {e.get('ResourceStatusReason')}")
            except Exception:
                pass
            raise AssertionError(f"stack {stack_name} failed to create: {status}; failed resources: {events}")
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} did not reach CREATE_COMPLETE within {timeout_s}s (last={status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
