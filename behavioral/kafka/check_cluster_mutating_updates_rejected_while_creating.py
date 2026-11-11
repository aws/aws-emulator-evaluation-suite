"""cluster-mutating-updates-rejected-while-creating."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-mutating-updates-rejected-while-creating"
GROUP = 'cluster-state-guards'
SERVICES = ['kafka']

def _err(fn):
    """Call fn(); return the ClientError's (code, message). An accepted call fails the check."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was accepted; a ClientError refusal was expected")


_DEFAULT_KAFKA_VERSION = "3.9.x"
_PROVISIONED_INSTANCE_TYPE = "kafka.m5.large"


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


def _cluster_current_version(msk, cluster_arn):
    return msk.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]["CurrentVersion"]


def _cluster_state(msk, cluster_arn):
    return msk.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]["State"]


def _wait_cluster_active(msk, cluster_arn, timeout_s=2700.0, interval_s=20.0):
    """Bounded poll CREATING -> ACTIVE. Raises on FAILED or timeout; never returns a
    non-ACTIVE state, so a caller can trust the returned version to be usable in a
    mutating call immediately."""
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        info = msk.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]
        last_state = info["State"]
        if last_state == "ACTIVE":
            return info["CurrentVersion"]
        if last_state == "FAILED":
            raise AssertionError(f"cluster {cluster_arn} entered FAILED while waiting for ACTIVE")
        time.sleep(interval_s)
    raise AssertionError(
        f"cluster {cluster_arn} did not reach ACTIVE within {timeout_s}s (last state={last_state})"
    )


STATE_REFUSAL_CODES = (
    "BadRequestException",
    "ClusterStateUnknownException",
    "InternalServerErrorException",
)

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """While a cluster is CREATING, storage, monitoring, security and broker-count updates and a
    bogus CurrentVersion are refused with no state change; once ACTIVE, UpdateMonitoring succeeds.
    """
    msk = ctx.client("kafka")
    arn = _shared_creating_cluster(ctx, msk)
    version = _cluster_current_version(msk, arn)
    before = msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["Provisioned"][
        "NumberOfBrokerNodes"
    ]
    assert _cluster_state(msk, arn) == "CREATING"

    codes = {
        "UpdateBrokerStorage": _err(
            lambda: msk.update_broker_storage(
                ClusterArn=arn,
                CurrentVersion=version,
                TargetBrokerEBSVolumeInfo=[
                    {"KafkaBrokerNodeId": "ALL", "VolumeSizeGB": 200}
                ],
            )
        ),
        "UpdateMonitoring": _err(
            lambda: msk.update_monitoring(
                ClusterArn=arn,
                CurrentVersion=version,
                EnhancedMonitoring="PER_TOPIC_PER_PARTITION",
            )
        ),
        "UpdateSecurity": _err(
            lambda: msk.update_security(
                ClusterArn=arn,
                CurrentVersion=version,
                EncryptionInfo={"EncryptionInTransit": {"ClientBroker": "TLS"}},
            )
        ),
        # Stale/never-issued optimistic-concurrency token.
        "UpdateMonitoring(staleVersion)": _err(
            lambda: msk.update_monitoring(
                ClusterArn=arn,
                CurrentVersion="K0THISVERSIONISWRONG",
                EnhancedMonitoring="PER_BROKER",
            )
        ),
    }

    bad = {op: code for op, (code, _message) in codes.items() if code != "BadRequestException"}
    assert not bad, f"expected BadRequestException from CREATING state, got {bad}"
    state_message = "This operation is only valid for resources that are in one of the following states :[ACTIVE]"
    expected_messages = {
        "UpdateBrokerStorage": state_message,
        "UpdateMonitoring": state_message,
        "UpdateSecurity": state_message,
        "UpdateMonitoring(staleVersion)": "One or more of the parameters are not valid.",
    }
    messages = {op: message for op, (_code, message) in codes.items()}
    assert messages == expected_messages, f"refusal messages from CREATING state: {messages}"

    # Real MSK answers UpdateBrokerCount with InternalServerErrorException, not BadRequestException.
    broker_count_code, broker_count_message = _err(
        lambda: msk.update_broker_count(
            ClusterArn=arn, CurrentVersion=version, TargetNumberOfBrokerNodes=4
        )
    )
    assert broker_count_code in STATE_REFUSAL_CODES, (
        f"UpdateBrokerCount must be rejected while CREATING, got {broker_count_code}"
    )
    if broker_count_code == "ClusterStateUnknownException":
        # The message lists the cluster's broker ENI ids, which the check never sees.
        assert broker_count_message.startswith(
            "To prevent further degradation of the cluster, Amazon MSK rejected the operation. The "
            "following required resource(s) are no longer accessible to the Amazon MSK service: [eni-"
        ) and broker_count_message.endswith(
            "]. We recommend that you immediately migrate any critical data from this cluster to a new "
            "cluster, and that you stop all production usage of this cluster. For more details or "
            "assistance, contact AWS Support."
        ), f"UpdateBrokerCount refusal message: {broker_count_message!r}"

    # None of the refusals may have advanced state, version or broker count.
    after = msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["Provisioned"][
        "NumberOfBrokerNodes"
    ]
    assert after == before, (before, after)
    assert _cluster_state(msk, arn) == "CREATING"
    assert _cluster_current_version(msk, arn) == version

    # Positive control: once ACTIVE, the identical UpdateMonitoring call is accepted, so the
    # refusals above are the state guard. One op only: MSK serializes cluster operations.
    active_version = _wait_cluster_active(msk, arn)
    restored = msk.update_monitoring(
        ClusterArn=arn, CurrentVersion=active_version, EnhancedMonitoring="PER_TOPIC_PER_PARTITION"
    )
    op_arn = restored.get("ClusterOperationArn")
    assert op_arn, f"UpdateMonitoring on an ACTIVE cluster must be accepted, got {restored}"

    # Independent read, through a THIRD operation: the accepted mutation must be visible via
    # DescribeClusterOperationV2, not just echoed back in the call that created it.
    op_state = msk.describe_cluster_operation_v2(ClusterOperationArn=op_arn)["ClusterOperationInfo"][
        "OperationState"
    ]
    assert op_state in ("PENDING", "UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"), (
        f"accepted UpdateMonitoring operation must be observable and progressing, got {op_state}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
