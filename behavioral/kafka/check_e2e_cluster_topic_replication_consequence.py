"""e2e-cluster-topic-replication-consequence."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-cluster-topic-replication-consequence"
GROUP = "e2e"
SERVICES = ["kafka"]

_MANAGED_TAG = {"sim2real:managed": "true"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:eventing", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A running MSK Replicator actually copies a topic created on the source
    cluster onto the target cluster -- observed via DescribeTopic on the target,
    not merely a RUNNING ReplicatorState."""
    kafka = ctx.client("kafka")
    infra = _create_vpc_infra(ctx)
    version = _pick_kafka_version(ctx, kafka)

    source_arn = _create_provisioned_cluster(ctx, kafka, "src", infra["subnet_ids"], infra["sg_id"], version)
    target_arn = _create_provisioned_cluster(ctx, kafka, "tgt", infra["subnet_ids"], infra["sg_id"], version)
    _wait_for_cluster_active(ctx, kafka, source_arn)
    _wait_for_cluster_active(ctx, kafka, target_arn)

    topic_name = ctx.unique_name("sim2real-behav-topic-")
    kafka.create_topic(ClusterArn=source_arn, TopicName=topic_name, PartitionCount=1, ReplicationFactor=2)
    _wait_for_topic_active(ctx, kafka, source_arn, topic_name)

    role_arn = _create_replicator_role(ctx)
    replicator_name = ctx.unique_name("sim2real-behav-repl-")
    kafka_clusters = [
        {
            "AmazonMskCluster": {"MskClusterArn": source_arn},
            "VpcConfig": {"SubnetIds": infra["subnet_ids"], "SecurityGroupIds": [infra["sg_id"]]},
        },
        {
            "AmazonMskCluster": {"MskClusterArn": target_arn},
            "VpcConfig": {"SubnetIds": infra["subnet_ids"], "SecurityGroupIds": [infra["sg_id"]]},
        },
    ]
    replication_info = [
        {
            "SourceKafkaClusterArn": source_arn,
            "TargetKafkaClusterArn": target_arn,
            "TargetCompressionType": "NONE",
            "TopicReplication": {
                "TopicsToReplicate": [topic_name],
                "CopyTopicConfigurations": True,
                "CopyAccessControlListsForTopics": False,
                "DetectAndCopyNewTopics": False,
                "TopicNameConfiguration": {"Type": "IDENTICAL"},
            },
            "ConsumerGroupReplication": {"ConsumerGroupsToReplicate": [".*"]},
        }
    ]
    replicator_arn = _create_replicator_with_retry(
        ctx, kafka, replicator_name, role_arn, kafka_clusters, replication_info
    )
    ctx.on_cleanup(lambda: _delete_replicator(ctx, kafka, replicator_arn))

    _wait_for_replicator_running(ctx, kafka, replicator_arn)

    topic = _wait_for_topic_active(ctx, kafka, target_arn, topic_name, timeout_s=900, interval_s=15)
    assert topic["TopicName"] == topic_name, (
        f"target cluster topic name mismatch: expected {topic_name!r}, got {topic.get('TopicName')!r}"
    )
    assert topic["Status"] == "ACTIVE", (
        f"replicated topic {topic_name!r} on target cluster is not ACTIVE: status={topic.get('Status')!r}"
    )




def _tag_spec(resource_type, name):
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real:managed", "Value": "true"}],
    }


def _create_vpc_infra(ctx, count=3):
    # THREE AZs, not two, because `NumberOfBrokerNodes` below is `len(subnets)` and MSK
    # Replicator refuses a cluster with fewer than three brokers: the replicator reaches FAILED with {'Code': 'InvalidInput.InvalidKafkaCluster', 'Message':
    # 'The specified Amazon MSK Cluster has less than 3 brokers.'} after both 2-broker clusters
    # reach ACTIVE, so the rejection is the replicator's, not the cluster's.
    """Adopt the run's shared network when it has one; provision a VPC (a scarce quota slot)
    only when there is none to adopt."""
    ec2 = ctx.client("ec2")
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        vpc_id = default_vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= count:
            sg_id = ec2.describe_security_groups(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
            )["SecurityGroups"][0]["GroupId"]
            return {"vpc_id": vpc_id, "subnet_ids": list(by_az.values())[:count], "sg_id": sg_id}

    name = ctx.unique_name("sim2real-behav-kafka-net-")
    vpc_id = ec2.create_vpc(CidrBlock="10.91.0.0/16", TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    azs = ec2.describe_availability_zones()["AvailabilityZones"]
    az_names = [a["ZoneName"] for a in azs[:count]]
    if len(az_names) < count:
        raise AssertionError(f"region {ctx.region} does not offer at least {count} availability zones")

    subnet_ids = []
    for i, az in enumerate(az_names):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.91.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec("subnet", f"{name}-{i}")],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(sid)

    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real MSK cluster-topic-replication check network",
        VpcId=vpc_id,
        TagSpecifications=[_tag_spec("security-group", name)],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": sg_id}]}],
    )
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": sg_id}


def _pick_kafka_version(ctx, kafka):
    versions = kafka.list_kafka_versions()["KafkaVersions"]
    active = [v["Version"] for v in versions if v.get("Status") == "ACTIVE"]
    if "3.9.x" in active:  # recommended, still ZooKeeper; older Standard versions are refused
        return "3.9.x"
    return (active or [v["Version"] for v in versions])[0]


def _create_provisioned_cluster(ctx, kafka, role, subnets, sg, version):
    name = ctx.unique_name(f"sim2real-behav-kafka-{role}-")
    resp = kafka.create_cluster_v2(
        ClusterName=name,
        Provisioned={
            "BrokerNodeGroupInfo": {
                # m5.large, not t3.small: MSK Replicator refuses a t3.small source, even with three
                # brokers per cluster, reaching FAILED with {'Code': 'InvalidInput.UnsupportedBrokerInstanceType',
                # 'Message': 'The Broker Instance Type is not supported for cluster ARN: ...'}.
                "InstanceType": "kafka.m5.large",
                "ClientSubnets": subnets,
                "SecurityGroups": [sg],
                "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 10}},
            },
            # MSK Replicator refuses InvalidInput.InvalidKafkaCluster unless SASL/IAM auth is
            # enabled on every cluster it connects to.
            "ClientAuthentication": {"Sasl": {"Iam": {"Enabled": True}}},
            "KafkaVersion": version,
            "NumberOfBrokerNodes": len(subnets),
        },
        Tags=_MANAGED_TAG,
    )
    arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, kafka, arn))
    return arn


def _delete_cluster(ctx, kafka, arn):
    try:
        kafka.delete_cluster(ClusterArn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NotFoundException":
            return
        raise


def _delete_replicator(ctx, kafka, arn):
    try:
        kafka.delete_replicator(ReplicatorArn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NotFoundException":
            return
        raise


def _wait_for_cluster_active(ctx, kafka, arn, timeout_s=2700, interval_s=20):
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]
        last_state = info["State"]
        if last_state == "ACTIVE":
            return info
        if last_state == "FAILED":
            raise AssertionError(f"cluster {arn} entered FAILED state")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {arn} did not reach ACTIVE within {timeout_s}s (last={last_state})")


def _wait_for_replicator_running(ctx, kafka, arn, timeout_s=1200, interval_s=20):
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        info = kafka.describe_replicator(ReplicatorArn=arn)
        last_state = info["ReplicatorState"]
        if last_state == "RUNNING":
            return info
        if last_state == "FAILED":
            raise AssertionError(f"replicator {arn} entered FAILED state: {info.get('StateInfo')}")
        time.sleep(interval_s)
    raise AssertionError(f"replicator {arn} did not reach RUNNING within {timeout_s}s (last={last_state})")


def _wait_for_topic_active(ctx, kafka, cluster_arn, topic_name, timeout_s=180, interval_s=5):
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
    raise AssertionError(f"topic {topic_name} on {cluster_arn} did not become ACTIVE (last status={last})")


def _create_replicator_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-kafka-repl-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "kafka.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSMSKReplicatorExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _create_replicator_with_retry(
    ctx, kafka, name, role_arn, kafka_clusters, replication_info, timeout_s=180.0, interval_s=15.0
):
    # IAM trust-policy propagation is eventually consistent: CreateReplicator can reject the
    # freshly-created role before kafka.amazonaws.com is able to assume it. Retry on that specific
    # window instead of guessing its length with a blind sleep.
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return kafka.create_replicator(
                ReplicatorName=name,
                ServiceExecutionRoleArn=role_arn,
                KafkaClusters=kafka_clusters,
                ReplicationInfoList=replication_info,
                Tags=_MANAGED_TAG,
            )["ReplicatorArn"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(
        f"CreateReplicator did not succeed within {timeout_s}s of role creation (last error: {last_exc})"
    )


# AWS-managed ENIs (clusters, endpoints, functions, ...) leave a VPC asynchronously after their
# owner's delete returns, so an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with
# DependencyViolation. Wait (bounded) for the ENIs to go, retry DependencyViolation inside the same
# window, and raise a final failure naming the ENIs still attached. The window is shared by all of
# one check's network deletes and fits the 900s cleanup budget.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
