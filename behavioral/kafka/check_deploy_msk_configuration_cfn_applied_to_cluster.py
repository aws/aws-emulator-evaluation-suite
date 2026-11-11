"""deploy-msk-configuration-cfn-applied-to-cluster."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags

CHECK = "deploy-msk-configuration-cfn-applied-to-cluster"
GROUP = "deploy"
SERVICES = ["kafka"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  SubnetId1:
    Type: String
  SubnetId2:
    Type: String
  KafkaVersion:
    Type: String
Resources:
  MskConfig:
    Type: AWS::MSK::Configuration
    Properties:
      Name: !Sub '${AWS::StackName}-config'
      ServerProperties: "auto.create.topics.enable=true\\ndefault.replication.factor=2\\n"
      KafkaVersionsList:
        - !Ref KafkaVersion
  MSKCluster:
    Type: AWS::MSK::Cluster
    Properties:
      ClusterName: !Sub '${AWS::StackName}-cluster'
      KafkaVersion: !Ref KafkaVersion
      NumberOfBrokerNodes: 2
      BrokerNodeGroupInfo:
        InstanceType: kafka.m5.large
        ClientSubnets:
          - !Ref SubnetId1
          - !Ref SubnetId2
      ConfigurationInfo:
        Arn: !Ref MskConfig
        Revision: 1
Outputs:
  ClusterArn:
    Value: !Ref MSKCluster
  ConfigArn:
    Value: !Ref MskConfig
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """DescribeClusterV2 CurrentBrokerSoftwareInfo ConfigurationArn/Revision match the stack's
    AWS::MSK::Configuration, not merely that both resources reached *_COMPLETE."""
    cfn = ctx.client("cloudformation")
    kafka = ctx.client("kafka")
    subnet_ids, _sg_id = _default_vpc_two_az_subnets(ctx)
    kafka_version = _pick_kafka_version(kafka)

    stack_name = ctx.unique_name("sim2real-msk-cfg-cfn-")
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_name))

    for attempt in range(2):
        cfn.create_stack(
            StackName=stack_name,
            TemplateBody=_TEMPLATE,
            Parameters=[
                {"ParameterKey": "SubnetId1", "ParameterValue": subnet_ids[0]},
                {"ParameterKey": "SubnetId2", "ParameterValue": subnet_ids[1]},
                {"ParameterKey": "KafkaVersion", "ParameterValue": kafka_version},
            ],
        )
        try:
            _wait_stack_status(
                cfn, stack_name, {"CREATE_COMPLETE"}, {"ROLLBACK_COMPLETE", "CREATE_FAILED", "ROLLBACK_FAILED"}
            )
            break
        except AssertionError as e:
            # ListKafkaVersions' ACTIVE set includes versions MSK has not yet enabled for
            # Standard broker instance types; CreateCluster's own rejection enumerates the
            # actually-compatible set, so retry once with the version AWS just reported.
            retry_version = _retry_version_for_standard_brokers(str(e)) if attempt == 0 else None
            if retry_version is None or retry_version == kafka_version:
                raise
            _delete_stack_and_wait(cfn, stack_name)
            stack_name = ctx.unique_name("sim2real-msk-cfg-cfn-")
            kafka_version = retry_version

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    }
    cluster_arn = outputs["ClusterArn"]
    config_arn = outputs["ConfigArn"]

    cluster_info = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]
    assert cluster_info["State"] == "ACTIVE", (
        f"expected cluster state ACTIVE, got {cluster_info['State']!r}"
    )
    software_info = cluster_info["Provisioned"]["CurrentBrokerSoftwareInfo"]
    assert software_info["ConfigurationArn"] == config_arn, (
        f"cluster is running configuration {software_info.get('ConfigurationArn')!r}, "
        f"expected the CFN-deployed configuration {config_arn!r}"
    )
    assert software_info["ConfigurationRevision"] == 1, (
        f"expected the cluster's active configuration revision to be 1, "
        f"got {software_info.get('ConfigurationRevision')!r}"
    )

    described_config = kafka.describe_configuration(Arn=config_arn)
    assert described_config["Arn"] == config_arn, (
        f"expected DescribeConfiguration to echo {config_arn!r}, got {described_config.get('Arn')!r}"
    )
    assert described_config["LatestRevision"]["Revision"] == 1, (
        f"expected the configuration's latest revision to be 1, "
        f"got {described_config['LatestRevision'].get('Revision')!r}"
    )


def _default_vpc_two_az_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("account has no shared network VPC to place the MSK cluster in")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network does not span at least 2 Availability Zones")
    subnet_ids = list(by_az.values())[:2]
    sg_id = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]
    return subnet_ids, sg_id


def _pick_kafka_version(kafka) -> str:
    # Standard brokers accept 3.9.x; they reject older versions and the Express-only 4.2.x.
    status = {v["Version"]: v.get("Status") for v in kafka.list_kafka_versions().get("KafkaVersions", [])}
    if status.get("3.9.x") != "ACTIVE":
        raise AssertionError(f"Kafka 3.9.x is not ACTIVE in ListKafkaVersions: {sorted(status)}")
    return "3.9.x"


def _retry_version_for_standard_brokers(reason: str) -> str | None:
    match = re.search(r"not supported for Kafka version .*?Valid values: \[(.*?)\]", reason)
    if not match:
        return None
    candidates = [v.strip() for v in match.group(1).split(",") if v.strip()]
    return sorted(candidates)[-1] if candidates else None


def _wait_stack_status(cfn, stack_name, success_states, failure_states, timeout_s=2400.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in success_states:
            return status
        if status in failure_states:
            raise AssertionError(
                f"stack {stack_name} entered failure state {status}: "
                f"{_failed_resource_reasons(cfn, stack_name)}"
            )
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not settle within {timeout_s}s, last status {status}")


def _failed_resource_reasons(cfn, stack_name) -> str:
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    reasons = [
        f"{e['LogicalResourceId']}[{e['ResourceStatus']}]: {e.get('ResourceStatusReason', 'no reason given')}"
        for e in events
        if e.get("ResourceStatusReason")
    ]
    return "; ".join(reasons) if reasons else "no resource events carried a reason"


def _delete_stack_and_wait(cfn, stack_name, timeout_s=2400.0, interval_s=20.0):
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except Exception:
            return
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} failed to delete, status {status}")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not finish deleting within {timeout_s}s, last status {status!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
