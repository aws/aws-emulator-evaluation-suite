"""replicator-create-invalid-role-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "replicator-create-invalid-role-rejected"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

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


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


_DEFAULT_KAFKA_VERSION = "3.9.x"
_PROVISIONED_INSTANCE_TYPE = "kafka.m5.large"

#: MSK Replicator refuses a cluster with fewer than 3 brokers (measured: with 2 the replicator is
#: ACCEPTED and settles FAILED with InvalidInput.InvalidKafkaCluster "less than 3 brokers"), and
#: NumberOfBrokerNodes must be a multiple of the client-subnet count, so brokers and AZ spread move
#: together. Without this, a target cluster shape -- not the role -- would be why the replicator
#: fails, which is exactly the confound this check exists to remove.
_REPLICATOR_MIN_BROKERS = 3


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


def _create_cluster_network(ctx, num_subnets=_REPLICATOR_MIN_BROKERS):
    """Shared per-check discovered network (memoized on ctx)."""
    if not hasattr(ctx, "_kafka_net"):
        ctx._kafka_net = _discover_network(ctx, minimum_subnets=_REPLICATOR_MIN_BROKERS)
    vpc_id, subnet_ids, sg_id = ctx._kafka_net
    if num_subnets > len(subnet_ids):
        raise AssertionError(f"discovered network only has {len(subnet_ids)} subnets, need {num_subnets}")
    return vpc_id, subnet_ids[:num_subnets], sg_id


def _provisioned_body(subnet_ids, sg_id, num_brokers=_REPLICATOR_MIN_BROKERS,
                      kafka_version=_DEFAULT_KAFKA_VERSION,
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


def _create_basic_cluster(ctx, msk, num_brokers=_REPLICATOR_MIN_BROKERS,
                          num_subnets=_REPLICATOR_MIN_BROKERS, kafka_version=_DEFAULT_KAFKA_VERSION,
                          name_prefix="cluster-", tags=None):
    """Create a PROVISIONED, SASL/IAM cluster (returns immediately, state CREATING). Registers
    DeleteCluster teardown that waits for the cluster to settle. Returns (arn, name, subnet_ids, sg_id).

    SASL/IAM is required: MSK Replicator reaches both clusters over port 9098 (IAM access
    control) and nothing else, so a cluster without it can never host a replicator -- which
    would confound a role-only negative with a cluster-shape one.
    """
    name = ctx.unique_name("sim2real-behav-" + name_prefix)
    _, subnet_ids, sg_id = _create_cluster_network(ctx, num_subnets=num_subnets)
    prov = _provisioned_body(subnet_ids, sg_id, num_brokers=num_brokers, kafka_version=kafka_version)
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


def _wait_cluster_active(msk, arn, timeout_s=2700, interval_s=30):
    """Poll DescribeCluster (v1) until the cluster settles ACTIVE or FAILED."""
    info = _poll_until(
        lambda: msk.describe_cluster(ClusterArn=arn)["ClusterInfo"],
        lambda i: i.get("State") in ("ACTIVE", "FAILED"),
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"cluster {arn} to settle",
    )
    if info.get("State") != "ACTIVE":
        raise AssertionError(f"cluster reached {info.get('State')} instead of ACTIVE")
    return info


def _two_active_clusters(ctx, msk, source_prefix, target_prefix):
    """Both clusters ACTIVE, provisioned CONCURRENTLY (CreateClusterV2 returns immediately, so
    issuing both before either wait overlaps the two ~20 min provisions -- cost is max(), not sum())."""
    source_arn, _sn, _ss, _sg = _create_basic_cluster(ctx, msk, name_prefix=source_prefix)
    target_arn, _tn, _ts, _tg = _create_basic_cluster(ctx, msk, name_prefix=target_prefix)
    _wait_cluster_active(msk, source_arn)
    _wait_cluster_active(msk, target_arn)
    return source_arn, target_arn


def _kafka_cluster_entry(msk, cluster_arn):
    """One CreateReplicator KafkaClusters entry, networked like the cluster itself: same-region
    replication needs security groups on BOTH clusters accepting the replicator's egress on 9098,
    which reusing the cluster's own group satisfies via the VPC default group's self-referencing rule."""
    bng = msk.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]["BrokerNodeGroupInfo"]
    vpc_config = {"SubnetIds": bng["ClientSubnets"]}
    if bng.get("SecurityGroups"):
        vpc_config["SecurityGroupIds"] = bng["SecurityGroups"]
    return {"AmazonMskCluster": {"MskClusterArn": cluster_arn}, "VpcConfig": vpc_config}


def _replication_info(source_arn, target_arn):
    return {
        "SourceKafkaClusterArn": source_arn,
        "TargetKafkaClusterArn": target_arn,
        "TargetCompressionType": "NONE",
        "TopicReplication": {"TopicsToReplicate": [".*"]},
        "ConsumerGroupReplication": {"ConsumerGroupsToReplicate": [".*"]},
    }


def _wait_replicator_state(msk, arn, states, timeout_s=2700, interval_s=20):
    return _poll_until(
        lambda: msk.describe_replicator(ReplicatorArn=arn),
        lambda i: i.get("ReplicatorState") in states,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"replicator {arn} to reach {states}",
    )


def _bogus_role_arn(ctx):
    """A well-formed IAM role ARN, in this account, that was never created."""
    return f"arn:aws:iam::{_account_id(ctx)}:role/{ctx.unique_name('sim2real-behav-nonexistent-role-')}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateReplicator between two ACTIVE IAM-auth clusters with a nonexistent ServiceExecutionRoleArn
    returns CREATING, then settles FAILED with a role-related message and is listed as FAILED."""
    msk = ctx.client("kafka")
    source_arn, target_arn = _two_active_clusters(ctx, msk, "repl-badrole-src-", "repl-badrole-tgt-")
    bogus_role = _bogus_role_arn(ctx)
    name = ctx.unique_name("sim2real-behav-replicator-badrole-")

    resp = msk.create_replicator(
        ReplicatorName=name,
        ServiceExecutionRoleArn=bogus_role,
        KafkaClusters=[
            _kafka_cluster_entry(msk, source_arn),
            _kafka_cluster_entry(msk, target_arn),
        ],
        ReplicationInfoList=[_replication_info(source_arn, target_arn)],
        Tags={"sim2real:managed": "true"},
    )
    arn = resp["ReplicatorArn"]
    assert resp.get("ReplicatorState") == "CREATING", (
        f"expected CreateReplicator to accept and go CREATING (validation is asynchronous), "
        f"got {resp.get('ReplicatorState')!r}"
    )

    # Wait for it to be GONE (not merely accepted): a live replicator holds its clusters and LIFO
    # runs the cluster teardowns right after this one.
    ctx.on_cleanup(lambda _a=arn: _drop_replicator(msk, _a))

    # Terminal read: an independent DescribeReplicator, not the CreateReplicator response.
    info = _wait_replicator_state(msk, arn, ("RUNNING", "FAILED"))
    assert info["ReplicatorState"] == "FAILED", (
        f"a nonexistent ServiceExecutionRoleArn must never let the replicator reach RUNNING; "
        f"got {info['ReplicatorState']}: {info.get('StateInfo')}"
    )
    state_info = info.get("StateInfo") or {}
    message = state_info.get("Message", "")
    assert "role" in message.lower() or "assume" in message.lower(), (
        f"expected the FAILED reason to name the service-execution role, not a cluster problem "
        f"(both clusters are genuinely ACTIVE/SASL-IAM/3-broker here); got StateInfo={state_info!r}"
    )

    # Effect-absent at the destination: the never-viable replicator must not be listed as RUNNING.
    listed = {
        r["ReplicatorName"]: r.get("ReplicatorState")
        for r in msk.list_replicators(ReplicatorNameFilter=name).get("Replicators", [])
        if r.get("ReplicatorName") == name
    }
    assert listed.get(name) == "FAILED", listed


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
