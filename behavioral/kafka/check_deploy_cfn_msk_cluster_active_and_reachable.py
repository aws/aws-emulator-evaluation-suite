"""deploy-cfn-msk-cluster-active-and-reachable."""
from __future__ import annotations

import socket

from botocore.exceptions import WaiterError

from behavioral_harness import tags

CHECK = "deploy-cfn-msk-cluster-active-and-reachable"
GROUP = "server-side"
SERVICES = ["kafka"]

#: kafka.t3.small is rejected ("Unsupported InstanceType specified"); kafka.m5.large is the
#: cheapest accepted size.
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
        InstanceType: kafka.m5.large
        ClientSubnets: [!Ref SubnetId1, !Ref SubnetId2]
        SecurityGroups: [!Ref SecurityGroupId]
      Tags:
        sim2real: audit
Outputs:
  ClusterArn:
    Value: !Ref MskCluster
"""


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A cluster deployed via AWS::MSK::Cluster reaches ACTIVE with resolvable bootstrap
    brokers -- not merely a CloudFormation CREATE_COMPLETE status."""
    subnet_ids, sg_id = _default_subnets_and_sg(ctx, count=2)
    cfn = ctx.client("cloudformation")
    kafka = ctx.client("kafka")

    # ListKafkaVersions carries no instance-type-compatibility field, and KRaft-only versions
    # CREATE_FAIL for Standard brokers ("Standard instance types are not supported for Kafka
    # version 4.2.x.kraft"), so fall back to the next-highest ACTIVE version on that rejection.
    remaining = _kafka_versions_desc(ctx)
    while True:
        kafka_version = remaining.pop(0)
        stack_name = ctx.unique_name("sim2real-msk-cfn-")
        cluster_name = ctx.unique_name("sim2real-msk-")
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
            Tags=[{"Key": "sim2real", "Value": "audit"}],
        )
        ctx.on_cleanup(lambda sn=stack_name: _delete_stack(ctx, sn))
        try:
            cfn.get_waiter("stack_create_complete").wait(
                StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1350}
            )
            break
        except WaiterError as exc:
            reasons = _failed_resource_reasons(cfn, stack_name)
            retryable = remaining and any(
                "instance types are not supported for kafka version" in r.lower() for r in reasons
            )
            if not retryable:
                raise AssertionError(
                    f"stack {stack_name} did not reach CREATE_COMPLETE with KafkaVersion="
                    f"{kafka_version!r}: {exc}; failed resources: {reasons}"
                ) from exc

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    }
    cluster_arn = outputs["ClusterArn"]

    info = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]
    assert info["State"] == "ACTIVE", (
        f"cluster is {info['State']!r} right after stack CREATE_COMPLETE; a CFN deploy "
        "that reports success before the underlying cluster is actually ACTIVE is a stub"
    )

    brokers = kafka.get_bootstrap_brokers(ClusterArn=cluster_arn)
    broker_string = brokers.get("BootstrapBrokerString") or brokers.get("BootstrapBrokerStringTls")
    assert broker_string, "no bootstrap broker string returned for an ACTIVE cluster"
    hosts = [h.rsplit(":", 1)[0] for h in broker_string.split(",") if h]
    assert len(hosts) == 2, f"expected 2 bootstrap broker hosts (NumberOfBrokerNodes=2), got {hosts!r}"

    unresolved = []
    for host in hosts:
        try:
            socket.gethostbyname(ctx.endpoint_host(host, 9092)[0])
        except socket.gaierror:
            unresolved.append(host)
    assert not unresolved, (
        f"bootstrap broker hosts {unresolved} (of {hosts}) were not DNS-resolvable; the "
        "cluster's network plumbing was never actually stood up"
    )



def _default_subnets_and_sg(ctx, count: int = 2):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network in this account/region to place MSK broker ENIs")
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


def _kafka_versions_desc(ctx) -> list[str]:
    """ACTIVE Kafka versions, highest first; the caller retries down this list on a
    version/instance-type rejection because the API carries no compatibility field."""
    kafka = ctx.client("kafka")
    versions = kafka.list_kafka_versions().get("KafkaVersions", [])
    active = [v["Version"] for v in versions if v.get("Status") == "ACTIVE"]
    candidates = active or [v["Version"] for v in versions]
    if not candidates:
        raise AssertionError("ListKafkaVersions returned no usable Kafka version")
    return sorted(set(candidates), reverse=True)


def _failed_resource_reasons(cfn, stack_name: str) -> list[str]:
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    return [
        f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason', '')}"
        for e in events
        if e["ResourceStatus"].endswith("FAILED")
    ]


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
