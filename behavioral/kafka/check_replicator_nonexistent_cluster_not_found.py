"""replicator-nonexistent-cluster-not-found."""
from __future__ import annotations

import time

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "replicator-nonexistent-cluster-not-found"
GROUP = 'overly-permissive'
SERVICES = ['kafka']


def _gone_ok(fn, gone_code):
    """Call fn(); a ClientError with `gone_code` means the resource is already gone, anything else raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != gone_code:
            raise


def _delete_replicator(msk, arn, timeout_s=900.0):
    """Delete the replicator and wait until it is gone, so the cluster it holds can be deleted after it.
    DeleteReplicator refuses a replicator that is still CREATING, so that refusal is retried."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            msk.delete_replicator(ReplicatorArn=arn)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            if code != "BadRequestException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while time.monotonic() < deadline:
        try:
            msk.describe_replicator(ReplicatorArn=arn)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"replicator {arn} still exists {timeout_s:.0f}s after DeleteReplicator")


_DEFAULT_KAFKA_VERSION = "3.9.x"
_PROVISIONED_INSTANCE_TYPE = "kafka.m5.large"


def _account_id(ctx):
    if not hasattr(ctx, "_kafka_account_id"):
        ctx._kafka_account_id = ctx.client("sts").get_caller_identity()["Account"]
    return ctx._kafka_account_id


def _discover_network(ctx, minimum_subnets=2):
    """The run's shared network (ctx.network()): its VPC, up to three of its subnets in distinct
    availability zones, and the VPC's default security group."""
    net = ctx.network()
    zones = net.availability_zones
    assert len(zones) >= minimum_subnets, (
        f"the shared network has subnets in {len(zones)} availability zones, need {minimum_subnets}"
    )
    return net.vpc_id, [net.subnets[az] for az in zones][:3], net.security_group_id


def _create_cluster_network(ctx, num_subnets=2):
    """Shared per-check discovered network (memoized on ctx)."""
    if not hasattr(ctx, "_kafka_net"):
        ctx._kafka_net = _discover_network(ctx, minimum_subnets=2)
    vpc_id, subnet_ids, sg_id = ctx._kafka_net
    if num_subnets > len(subnet_ids):
        raise AssertionError(f"discovered network only has {len(subnet_ids)} subnets, need {num_subnets}")
    return vpc_id, subnet_ids[:num_subnets], sg_id


def _provisioned_body(subnet_ids, sg_id, num_brokers=2, kafka_version=_DEFAULT_KAFKA_VERSION,
                      instance_type=_PROVISIONED_INSTANCE_TYPE, volume_size=10):
    broker_info = {
        "InstanceType": instance_type,
        "ClientSubnets": subnet_ids,
        "StorageInfo": {"EbsStorageInfo": {"VolumeSize": volume_size}},
    }
    if sg_id:
        broker_info["SecurityGroups"] = [sg_id]
    return {
        "BrokerNodeGroupInfo": broker_info,
        "KafkaVersion": kafka_version,
        "NumberOfBrokerNodes": num_brokers,
    }


def _create_basic_cluster(ctx, msk, num_brokers=2, kafka_version=_DEFAULT_KAFKA_VERSION,
                          name_prefix="cluster-", tags=None):
    """Create a PROVISIONED cluster (returns immediately, state CREATING). Registers
    DeleteCluster teardown that waits for the cluster to settle. Returns (arn, name, subnet_ids, sg_id)."""
    name = ctx.unique_name("sim2real-behav-" + name_prefix)
    _, subnet_ids, sg_id = _create_cluster_network(ctx, num_subnets=2)
    kwargs = {
        "ClusterName": name,
        "Provisioned": _provisioned_body(
            subnet_ids, sg_id, num_brokers=num_brokers, kafka_version=kafka_version
        ),
        "Tags": {"sim2real:managed": "true", **(tags or {})},
    }
    try:
        resp = msk.create_cluster_v2(**kwargs)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        raise AssertionError(
            f"could not create an MSK cluster for this check ({code}: {exc}); "
            f"network used: vpc subnets={subnet_ids} sg={sg_id}"
        ) from exc
    arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_when_settled(msk, arn))
    return arn, name, subnet_ids, sg_id


def _delete_cluster_when_settled(msk, arn, timeout_s=2400.0, interval_s=30.0):
    """DeleteCluster refuses a cluster that is CREATING or UPDATING, so wait for ACTIVE or FAILED first."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            state = msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"]
            if state == "DELETING":
                return
            if state in ("ACTIVE", "FAILED"):
                msk.delete_cluster(ClusterArn=arn)
                return
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {arn} still {state} after {timeout_s:.0f}s; it cannot be deleted")
        time.sleep(interval_s)


def _shared_creating_cluster(ctx, msk):
    """The check's own CREATING cluster, provisioned once per check (memoized on ctx)."""
    if not hasattr(ctx, "_kafka_shared_cluster"):
        arn, _name, _subnets, _sg = _create_basic_cluster(ctx, msk, name_prefix="shared-")
        ctx._kafka_shared_cluster = arn
    return ctx._kafka_shared_cluster


#: The managed policy AWS documents for a replicator service-execution role. CreateReplicator
#: validates ServiceExecutionRoleArn synchronously and rejects a role that does not exist with
#: BadRequestException -- before it ever gets to the cluster references. A fabricated role ARN here
#: would confound "nonexistent role" with "nonexistent cluster" and the check would never observe
#: the NotFoundException it exists to grade.
_SER_MANAGED_POLICY = "arn:aws:iam::aws:policy/service-role/AWSMSKReplicatorExecutionRole"


def _replicator_role_arn(ctx):
    """A real, in-check-created service-execution role, so the only broken thing is the source
    cluster ARN under test."""
    if getattr(ctx, "_kafka_ser_arn", None):
        return ctx._kafka_ser_arn
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-msk-ser-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "kafka.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": _account_id(ctx)}},
            }
        ],
    }
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real behavioral MSK Replicator service execution role",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]

    def _drop_role(_n=name):
        _gone_ok(lambda: iam.detach_role_policy(RoleName=_n, PolicyArn=_SER_MANAGED_POLICY), "NoSuchEntity")
        _gone_ok(lambda: iam.delete_role(RoleName=_n), "NoSuchEntity")

    ctx.on_cleanup(_drop_role)
    iam.attach_role_policy(RoleName=name, PolicyArn=_SER_MANAGED_POLICY)
    ctx._kafka_ser_arn = arn
    return arn


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateReplicator does NOT validate that the source cluster exists: with a resolvable target
    cluster and a real service-execution role, a well-formed but nonexistent source cluster ARN is
    ACCEPTED with a ReplicatorArn that DescribeReplicator reads back."""
    msk = ctx.client("kafka")
    role_arn = _replicator_role_arn(ctx)
    _vpc_id, subnet_ids, sg_id = _create_cluster_network(ctx, num_subnets=2)
    target_arn = _shared_creating_cluster(ctx, msk)
    region = ctx.region
    bogus_source = (
        f"arn:aws:kafka:{region}:{_account_id(ctx)}:cluster/"
        f"{ctx.unique_name('sim2real-behav-ghost-src-')}/{uuid.uuid4()}-2"
    )
    replicator_name = ctx.unique_name("sim2real-behav-replicator-nf-")

    def kafka_cluster(arn):
        return {
            "AmazonMskCluster": {"MskClusterArn": arn},
            "VpcConfig": {"SubnetIds": subnet_ids, "SecurityGroupIds": [sg_id] if sg_id else []},
        }

    def attempt():
        return msk.create_replicator(
            ReplicatorName=replicator_name,
            ServiceExecutionRoleArn=role_arn,
            KafkaClusters=[kafka_cluster(bogus_source), kafka_cluster(target_arn)],
            ReplicationInfoList=[
                {
                    "SourceKafkaClusterArn": bogus_source,
                    "TargetKafkaClusterArn": target_arn,
                    "TargetCompressionType": "NONE",
                    "TopicReplication": {"TopicsToReplicate": [".*"]},
                    "ConsumerGroupReplication": {"ConsumerGroupsToReplicate": [".*"]},
                }
            ],
            Tags={"sim2real:managed": "true"},
        )

    try:
        resp = attempt()
    except ClientError as exc:
        raise AssertionError(
            f"expected CreateReplicator to ACCEPT a nonexistent source cluster ARN "
            f"({bogus_source}), got error code {exc.response.get('Error', {}).get('Code')!r}"
        ) from exc
    replicator_arn = resp.get("ReplicatorArn")
    if replicator_arn:
        ctx.on_cleanup(lambda _a=replicator_arn: _delete_replicator(msk, _a))
    assert replicator_arn, f"CreateReplicator returned no ReplicatorArn: {resp!r}"
    # Accepted AND persisted: the replicator is readable back, so this is a real admission and
    # not a no-op 200.
    described = msk.describe_replicator(ReplicatorArn=replicator_arn)
    assert described["ReplicatorArn"] == replicator_arn, described


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
