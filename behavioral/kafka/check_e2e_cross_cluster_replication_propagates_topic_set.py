"""e2e-cross-cluster-replication-propagates-topic-set."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-cross-cluster-replication-propagates-topic-set"
GROUP = "e2e"
SERVICES = ["kafka"]

_KAFKA_VERSION = "3.9.x"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After UpdateReplicationInfo replaces a replicator's topic pattern, a fresh DescribeReplicator
    returns the new pattern in place of the initial one, not just the update request's echo."""
    kafka = ctx.client("kafka")
    infra = _create_vpc_infra(ctx)
    role_arn = _create_replicator_role(ctx)

    source_arn = _create_provisioned_cluster(ctx, kafka, infra, "src")
    target_arn = _create_provisioned_cluster(ctx, kafka, infra, "dst")

    vpc_config = {"SubnetIds": infra["subnet_ids"], "SecurityGroupIds": [infra["sg_id"]]}
    replicator_name = ctx.unique_name("sim2real-repl-")
    resp = _create_replicator_with_retry(
        kafka,
        replicator_name=replicator_name,
        role_arn=role_arn,
        source_arn=source_arn,
        target_arn=target_arn,
        vpc_config=vpc_config,
    )
    replicator_arn = resp["ReplicatorArn"]
    ctx.on_cleanup(lambda: _delete_replicator(ctx, kafka, replicator_arn))

    _wait_replicator_state(ctx, kafka, replicator_arn, {"RUNNING"}, timeout_s=2400.0)

    described_before = kafka.describe_replicator(ReplicatorArn=replicator_arn)
    before_patterns = described_before["ReplicationInfoList"][0]["TopicReplication"]["TopicsToReplicate"]
    assert before_patterns == ["sim2real-initial.*"]

    current_version = described_before["CurrentVersion"]
    kafka.update_replication_info(
        ReplicatorArn=replicator_arn,
        CurrentVersion=current_version,
        SourceKafkaClusterArn=source_arn,
        TargetKafkaClusterArn=target_arn,
        TopicReplication={
            "TopicsToReplicate": ["sim2real-expanded.*"],
            "TopicsToExclude": [],
            "CopyAccessControlListsForTopics": False,
            "CopyTopicConfigurations": True,
            "DetectAndCopyNewTopics": True,
        },
    )
    _wait_replicator_state(ctx, kafka, replicator_arn, {"RUNNING"}, timeout_s=1200.0)

    described_after = kafka.describe_replicator(ReplicatorArn=replicator_arn)
    after_patterns = described_after["ReplicationInfoList"][0]["TopicReplication"]["TopicsToReplicate"]
    assert after_patterns == ["sim2real-expanded.*"], (
        f"DescribeReplicator after UpdateReplicationInfo should show the new "
        f"replicated-topic set, got {after_patterns}"
    )
    assert after_patterns != before_patterns


def _error_code(fn):
    """Call fn(); return the code of the ClientError it raises, or "present" when it succeeds."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    return "present"


def _tag_spec(resource_type: str, name: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real:managed", "Value": "true"}],
    }


def _create_vpc_infra(ctx) -> dict:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-kafka-repl-")
    vpc_id = ec2.create_vpc(CidrBlock="10.82.0.0/16", TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", lambda: _teardown_deadline(ctx), VpcId=vpc_id))

    azs = ec2.describe_availability_zones()["AvailabilityZones"]
    az_names = [a["ZoneName"] for a in azs[:3]]
    subnet_ids = []
    for i, az in enumerate(az_names):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.82.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec("subnet", f"{name}-{i}")],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(
            lambda sid=sid: _delete_net(ec2, "delete_subnet", lambda: _teardown_deadline(ctx), SubnetId=sid)
        )
        subnet_ids.append(sid)

    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real kafka replication sg",
        VpcId=vpc_id,
        TagSpecifications=[_tag_spec("security-group", name)],
    )["GroupId"]
    ctx.on_cleanup(
        lambda: _delete_net(ec2, "delete_security_group", lambda: _teardown_deadline(ctx), GroupId=sg_id)
    )
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": sg_id}]}],
    )
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": sg_id}


def _create_replicator_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-kafka-repl-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "kafka.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = ctx.unique_name("sim2real-kafka-repl-policy-")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "kafka:*",
                    "kafka-cluster:*",
                    "ec2:CreateNetworkInterface",
                    "ec2:DescribeNetworkInterfaces",
                    "ec2:DeleteNetworkInterface",
                    "ec2:DescribeSecurityGroups",
                    "ec2:DescribeSubnets",
                    "ec2:DescribeVpcs",
                    "ec2:CreateVpcEndpoint",
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                "Resource": "*",
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_replicator_with_retry(
    kafka, *, replicator_name: str, role_arn: str, source_arn: str, target_arn: str, vpc_config: dict
):
    """CreateReplicator is the first call that assumes ``role_arn``; IAM's own eventual
    consistency means it can reject the still-fresh role with BadRequestException for a short
    window, so that refusal is retried to a bound; every other error raises at once."""
    deadline = time.monotonic() + 120.0
    while True:
        try:
            return kafka.create_replicator(
                ReplicatorName=replicator_name,
                ServiceExecutionRoleArn=role_arn,
                KafkaClusters=[
                    {"AmazonMskCluster": {"MskClusterArn": source_arn}, "VpcConfig": vpc_config},
                    {"AmazonMskCluster": {"MskClusterArn": target_arn}, "VpcConfig": vpc_config},
                ],
                ReplicationInfoList=[
                    {
                        "SourceKafkaClusterArn": source_arn,
                        "TargetKafkaClusterArn": target_arn,
                        "TargetCompressionType": "NONE",
                        "TopicReplication": {"TopicsToReplicate": ["sim2real-initial.*"]},
                        "ConsumerGroupReplication": {"ConsumerGroupsToReplicate": ["sim2real-initial.*"]},
                    }
                ],
                Tags={"sim2real:managed": "true"},
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "BadRequestException" or time.monotonic() >= deadline:
                raise
            time.sleep(2.0)


def _create_provisioned_cluster(ctx, kafka, infra: dict, suffix: str) -> str:
    name = ctx.unique_name(f"sim2real-kafka-repl-{suffix}")
    # MSK Replicator needs a Kafka version it supports on Standard brokers and reaches both clusters
    # over SASL/IAM only, so each cluster enables IAM client authentication.
    status = {v["Version"]: v.get("Status") for v in kafka.list_kafka_versions().get("KafkaVersions", [])}
    if status.get(_KAFKA_VERSION) != "ACTIVE":
        raise AssertionError(f"Kafka {_KAFKA_VERSION} is not ACTIVE in ListKafkaVersions: {sorted(status)}")

    resp = kafka.create_cluster(
        ClusterName=name,
        KafkaVersion=_KAFKA_VERSION,
        NumberOfBrokerNodes=3,
        ClientAuthentication={"Sasl": {"Iam": {"Enabled": True}}},
        BrokerNodeGroupInfo={
            "InstanceType": "kafka.m5.large",
            "ClientSubnets": infra["subnet_ids"],
            "SecurityGroups": [infra["sg_id"]],
            "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 100}},
        },
        Tags={"sim2real:managed": "true"},
    )
    cluster_arn = resp["ClusterArn"]

    def _cleanup_cluster():
        if _error_code(lambda: kafka.describe_cluster(ClusterArn=cluster_arn)) == "NotFoundException":
            return
        try:
            kafka.delete_cluster(ClusterArn=cluster_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
        _wait_cluster_gone(ctx, kafka, cluster_arn, timeout_s=_teardown_deadline(ctx) - time.monotonic())

    ctx.on_cleanup(_cleanup_cluster)
    _wait_cluster_state(ctx, kafka, cluster_arn, {"ACTIVE"}, timeout_s=3000.0)
    return cluster_arn


def _wait_cluster_state(ctx, kafka, cluster_arn: str, target_states: set, timeout_s: float = 1800.0) -> dict:
    deadline = time.monotonic() + timeout_s
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
    raise AssertionError(f"cluster never reached {target_states} (last={last})")


def _wait_cluster_gone(ctx, kafka, cluster_arn: str, timeout_s: float = 1800.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _error_code(lambda: kafka.describe_cluster(ClusterArn=cluster_arn)) == "NotFoundException":
            return
        time.sleep(2.0)
    raise AssertionError(f"cluster {cluster_arn} was not deleted within {timeout_s}s")


def _wait_replicator_state(ctx, kafka, replicator_arn: str, target_states: set, timeout_s: float = 1800.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_replicator(ReplicatorArn=replicator_arn)
        state = info["ReplicatorState"]
        last = state
        if state in target_states:
            return info
        if state == "FAILED":
            raise AssertionError(f"replicator entered FAILED: {info.get('StateInfo')}")
        time.sleep(2.0)
    raise AssertionError(f"replicator never reached {target_states} (last={last})")


def _delete_replicator(ctx, kafka, replicator_arn: str) -> None:
    if _error_code(lambda: kafka.describe_replicator(ReplicatorArn=replicator_arn)) == "NotFoundException":
        return
    try:
        kafka.delete_replicator(ReplicatorArn=replicator_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise
        return
    deadline = _teardown_deadline(ctx)
    while time.monotonic() < deadline:
        if _error_code(lambda: kafka.describe_replicator(ReplicatorArn=replicator_arn)) == "NotFoundException":
            return
        time.sleep(2.0)
    raise AssertionError(f"replicator {replicator_arn} still exists at the cleanup deadline after DeleteReplicator")


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes: a cluster or endpoint in
# this VPC deletes asynchronously, so its ENIs can still hold the subnet or security group and an
# immediate delete fails with DependencyViolation. The ENI wait and the DependencyViolation retries
# run to the run's one cleanup deadline, shared with the cluster teardown; a delete still refused
# then raises, naming the ENIs still attached.
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
#: The suite's cleanup budget; every teardown of one run shares a single deadline inside it.
_CLEANUP_BUDGET_S = 1800.0


def _teardown_deadline(ctx) -> float:
    """The run's one cleanup deadline, started by the first teardown that asks for it."""
    if getattr(ctx, "_kafka_teardown_deadline", None) is None:
        ctx._kafka_teardown_deadline = time.monotonic() + _CLEANUP_BUDGET_S
    return ctx._kafka_teardown_deadline


def _delete_net(client, op, deadline_fn, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    deadline = deadline_fn()
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
                        f"{op}({ident}): DependencyViolation at the cleanup deadline; "
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
