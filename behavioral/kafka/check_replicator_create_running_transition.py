"""replicator-create-running-transition."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "replicator-create-running-transition"
GROUP = 'cluster-lifecycle'
SERVICES = ['kafka']

_DEFAULT_KAFKA_VERSION = "3.9.x"
_PROVISIONED_INSTANCE_TYPE = "kafka.m5.large"


def _drop_replicator(msk, arn, timeout_s=900.0):
    """Delete the replicator and wait until DescribeReplicator answers NotFoundException.

    DeleteReplicator refuses a replicator still CREATING with BadRequestException; that is retried.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            msk.delete_replicator(ReplicatorArn=arn)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code != "BadRequestException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while time.monotonic() < deadline:
        try:
            msk.describe_replicator(ReplicatorArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"replicator {arn} still present {timeout_s:.0f}s after DeleteReplicator")


def _drop_role(iam, name, timeout_s=120.0):
    """Detach the managed policy, then delete the role; DeleteConflict is retried to a deadline."""
    try:
        iam.detach_role_policy(RoleName=name, PolicyArn=_SER_MANAGED_POLICY)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            iam.delete_role(RoleName=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchEntity":
                return
            if code != "DeleteConflict" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition", ctx=None):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _account_id(ctx):
    if not hasattr(ctx, "_kafka_account_id"):
        ctx._kafka_account_id = ctx.client("sts").get_caller_identity()["Account"]
    return ctx._kafka_account_id


def _discover_network(ctx, minimum_subnets=2):
    """The run's shared network: its VPC, up to three subnets in distinct AZs, and the default
    security group."""
    net = ctx.network()
    zones = net.availability_zones
    assert len(zones) >= minimum_subnets, (
        f"the shared network has subnets in {len(zones)} availability zones, need {minimum_subnets}"
    )
    return net.vpc_id, [net.subnets[az] for az in zones][:3], net.security_group_id


def _create_cluster_network(ctx, num_subnets=2):
    """The shared network, memoized on ctx."""
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


def _create_basic_cluster(ctx, msk, num_brokers=2, num_subnets=2,
                          kafka_version=_DEFAULT_KAFKA_VERSION,
                          name_prefix="cluster-", tags=None):
    """Start a PROVISIONED cluster and register its teardown; return (arn, name, subnet_ids, sg_id).

    MSK requires NumberOfBrokerNodes to be a multiple of the client-subnet count, hence num_subnets."""
    name = ctx.unique_name("sim2real-behav-" + name_prefix)
    _, subnet_ids, sg_id = _create_cluster_network(ctx, num_subnets=num_subnets)
    prov = _provisioned_body(subnet_ids, sg_id, num_brokers=num_brokers, kafka_version=kafka_version)
    # MSK Replicator reaches both clusters with IAM access control (port 9098) and nothing else,
    # so a cluster without SASL/IAM can never host a replicator. Unauthenticated access stays off,
    # which is what specifying ClientAuthentication at all does.
    prov["ClientAuthentication"] = {"Sasl": {"Iam": {"Enabled": True}}}
    kwargs = {
        "ClusterName": name,
        "Provisioned": prov,
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


def _delete_cluster_when_settled(msk, arn, timeout_s=2400.0, interval_s=2.0):
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


def _wait_cluster_active(ctx, msk, arn, timeout_s=2700, interval_s=1):
    """Poll DescribeCluster (v1) until the cluster settles; raise unless it is ACTIVE."""
    info = _poll_until(
        lambda: msk.describe_cluster(ClusterArn=arn)["ClusterInfo"],
        lambda i: i.get("State") in ("ACTIVE", "FAILED"),
        timeout_s=_budget_s(ctx, timeout_s),
        interval_s=interval_s,
        description=f"cluster {arn} to settle",
        ctx=ctx,
    )
    if info.get("State") != "ACTIVE":
        raise AssertionError(f"cluster reached {info.get('State')} instead of ACTIVE")
    return info


#: The managed policy AWS documents for a replicator service-execution role: read the source,
#: write the target. Anything less and the replicator creates, then settles FAILED. The
#: ``/service-role/`` path is part of the ARN -- the bare ``iam::aws:policy/<name>`` form is a
#: different, nonexistent policy and AttachRolePolicy answers NoSuchEntity for it.
_SER_MANAGED_POLICY = "arn:aws:iam::aws:policy/service-role/AWSMSKReplicatorExecutionRole"


def _replicator_role_arn(ctx):
    """ARN of the service-execution role MSK Replicator assumes to read source / write target.

    Created by the check (CreateReplicator rejects a nonexistent role), memoized on ctx, and made
    before the clusters so their provisioning time covers IAM propagation.
    """
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

    # Registered before any cluster or replicator teardown so LIFO runs it LAST -- deleting the
    # role while the replicator still holds it would fail.
    ctx.on_cleanup(lambda _n=name: _drop_role(iam, _n))
    iam.attach_role_policy(RoleName=name, PolicyArn=_SER_MANAGED_POLICY)
    ctx._kafka_ser_arn = arn
    return arn


def _replication_info(source_arn, target_arn):
    return {
        "SourceKafkaClusterArn": source_arn,
        "TargetKafkaClusterArn": target_arn,
        # REQUIRED by the API model (ReplicationInfo.required); omitting it fails botocore's
        # client-side parameter validation.
        "TargetCompressionType": "NONE",
        "TopicReplication": {
            "TopicsToReplicate": [".*"],
            "CopyTopicConfigurations": True,
            "CopyAccessControlListsForTopics": False,
            "DetectAndCopyNewTopics": False,
        },
        "ConsumerGroupReplication": {
            "ConsumerGroupsToReplicate": [".*"],
            "DetectAndCopyNewConsumerGroups": False,
            "SynchroniseConsumerGroupOffsets": False,
        },
    }


def _wait_replicator_state(ctx, msk, arn, states, timeout_s=2700, interval_s=1):
    info = _poll_until(
        lambda: msk.describe_replicator(ReplicatorArn=arn),
        lambda i: i.get("ReplicatorState") in states,
        timeout_s=_budget_s(ctx, timeout_s),
        interval_s=interval_s,
        description=f"replicator {arn} to reach {states}",
        ctx=ctx,
    )
    return info


def _active_cluster(ctx, msk, name_prefix, num_brokers=2):
    arn, _name, _subnets, _sg = _create_basic_cluster(ctx, msk, num_brokers=num_brokers, name_prefix=name_prefix)
    _wait_cluster_active(ctx, msk, arn)
    return arn


#: MSK Replicator refuses a cluster with fewer than 3 brokers: with 2 the
#: replicator is ACCEPTED and then settles FAILED with
#: InvalidInput.InvalidKafkaCluster "The specified Amazon MSK Cluster has less than 3 brokers".
#: MSK separately requires NumberOfBrokerNodes to be a multiple of the client-subnet count, so the
#: broker count and the AZ spread have to move together.
_REPLICATOR_MIN_BROKERS = 3


def _two_active_clusters(ctx, msk, source_prefix, target_prefix,
                         num_brokers=_REPLICATOR_MIN_BROKERS, num_subnets=_REPLICATOR_MIN_BROKERS):
    """Both clusters ACTIVE, provisioned concurrently so the ~20 min builds overlap."""
    source_arn, _sn, _ss, _sg = _create_basic_cluster(
        ctx, msk, num_brokers=num_brokers, num_subnets=num_subnets, name_prefix=source_prefix
    )
    target_arn, _tn, _ts, _tg = _create_basic_cluster(
        ctx, msk, num_brokers=num_brokers, num_subnets=num_subnets, name_prefix=target_prefix
    )
    _wait_cluster_active(ctx, msk, source_arn)
    _wait_cluster_active(ctx, msk, target_arn)
    return source_arn, target_arn


def _kafka_cluster_entry(msk, cluster_arn):
    """One CreateReplicator KafkaClusters entry, networked like the cluster itself.

    Same-region replication needs security groups on BOTH clusters: the replicator's groups must
    allow egress to the cluster's groups on 9098 (IAM access control) and the cluster's groups must
    accept it. Reusing the cluster's own group satisfies that through the VPC default group's
    self-referencing rule.
    """
    bng = msk.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]["BrokerNodeGroupInfo"]
    vpc_config = {"SubnetIds": bng["ClientSubnets"]}
    if bng.get("SecurityGroups"):
        vpc_config["SecurityGroupIds"] = bng["SecurityGroups"]
    return {"AmazonMskCluster": {"MskClusterArn": cluster_arn}, "VpcConfig": vpc_config}


def _create_replicator(ctx, msk, source_arn, target_arn, name_prefix):
    name = ctx.unique_name(name_prefix)
    resp = msk.create_replicator(
        ReplicatorName=name,
        ServiceExecutionRoleArn=_replicator_role_arn(ctx),
        KafkaClusters=[
            _kafka_cluster_entry(msk, source_arn),
            _kafka_cluster_entry(msk, target_arn),
        ],
        ReplicationInfoList=[_replication_info(source_arn, target_arn)],
        Tags={"sim2real:managed": "true"},
    )
    arn = resp["ReplicatorArn"]

    # Wait for it to be GONE, not merely accepted: a replicator holds its source and target
    # clusters, so the DeleteCluster teardowns that run after this one (LIFO) are refused meanwhile.
    ctx.on_cleanup(lambda _a=arn: _drop_replicator(msk, _a))
    return arn, name


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateReplicator between two ACTIVE SASL/IAM clusters settles in RUNNING, not FAILED
    (MSK Replicator speaks only IAM access control).
    """
    msk = ctx.client("kafka")
    # Before the clusters: a role rejected at CreateReplicator would waste both provisions, and
    # the wait below doubles as IAM propagation time.
    _replicator_role_arn(ctx)
    source_arn, target_arn = _two_active_clusters(ctx, msk, "repl-src-", "repl-tgt-")

    replicator_arn, name = _create_replicator(ctx, msk, source_arn, target_arn, "sim2real-behav-replicator-")
    info = _wait_replicator_state(ctx, msk, replicator_arn, ("RUNNING", "FAILED"))
    # StateInfo carries WHY a replicator failed; without it a FAILED verdict says only "not RUNNING".
    assert info["ReplicatorState"] == "RUNNING", (
        f"replicator did not reach RUNNING, got {info['ReplicatorState']}: {info.get('StateInfo')}"
    )
    assert info["ReplicatorName"] == name, info


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
