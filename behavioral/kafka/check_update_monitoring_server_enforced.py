"""update-monitoring-server-enforced."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-monitoring-server-enforced"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

_DEFAULT_KAFKA_VERSION = "3.9.x"
_PROVISIONED_INSTANCE_TYPE = "kafka.m5.large"


_NOT_FOUND = ("NotFoundException", "The requested resource doesn\u2019t exist.")
_STALE_VERSION = ("BadRequestException", "The version of the cluster isn\u2019t current. Check the current version and try again.")


def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) of the ClientError it raises.

    An unexpected SUCCESS raises with the actual result, because an emulator ACCEPTING a call real
    AWS refuses is the strongest signal available.
    """
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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


def _account_id(ctx):
    if not hasattr(ctx, "_kafka_account_id"):
        ctx._kafka_account_id = ctx.client("sts").get_caller_identity()["Account"]
    return ctx._kafka_account_id


def _bogus_cluster_arn(ctx):
    """A well-formed MSK cluster ARN, in this account, that cannot exist."""
    return (
        f"arn:aws:kafka:{ctx.region}:{_account_id(ctx)}:cluster/"
        f"{ctx.unique_name('sim2real-behav-nonexistent-')}/"
        "00000000-0000-0000-0000-000000000000-1"
    )


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


def _wait_cluster_v2_active(msk, arn, timeout_s=2700, interval_s=30):
    info = _poll_until(
        lambda: msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"],
        lambda i: i.get("State") in ("ACTIVE", "FAILED"),
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"cluster {arn} to settle",
    )
    if info.get("State") != "ACTIVE":
        raise AssertionError(f"cluster reached {info.get('State')} instead of ACTIVE")
    return info


def _wait_operation_complete(msk, operation_arn, timeout_s=600, interval_s=10):
    """Real AWS reports UPDATE_COMPLETE / UPDATE_FAILED here, not the bare COMPLETED/FAILED
    the DescribeClusterOperationV2 shape's field name would suggest -- measured on a live
    UPDATE_CLUSTER_MONITORING operation rather than assumed."""
    op = _poll_until(
        lambda: msk.describe_cluster_operation_v2(ClusterOperationArn=operation_arn)[
            "ClusterOperationInfo"
        ],
        lambda o: o.get("OperationState", "").endswith(("_COMPLETE", "_FAILED")),
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"cluster operation {operation_arn} to finish",
    )
    if not op.get("OperationState", "").endswith("_COMPLETE"):
        raise AssertionError(f"cluster operation {operation_arn} ended {op.get('OperationState')!r}: {op.get('ErrorInfo')}")
    return op


def _current_monitoring(msk, arn):
    return msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["Provisioned"]["EnhancedMonitoring"]


def _current_version(msk, arn):
    return msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["CurrentVersion"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateMonitoring sets PER_TOPIC_PER_BROKER on an ACTIVE cluster, a stale CurrentVersion is refused
    and changes nothing, the current version applies PER_TOPIC_PER_PARTITION, and a missing cluster fails
    with NotFoundException."""
    msk = ctx.client("kafka")
    arn, _name, _subnets, _sg = _create_basic_cluster(ctx, msk, num_brokers=2, name_prefix="monitor-")
    _wait_cluster_v2_active(msk, arn)

    baseline = _current_monitoring(msk, arn)
    version = _current_version(msk, arn)

    # --- positive control: a real cluster accepts a real monitoring-level change ---
    resp = msk.update_monitoring(
        ClusterArn=arn, CurrentVersion=version, EnhancedMonitoring="PER_TOPIC_PER_BROKER"
    )
    assert resp["ClusterArn"] == arn, resp
    _wait_operation_complete(msk, resp["ClusterOperationArn"])
    applied = _current_monitoring(msk, arn)
    assert applied == "PER_TOPIC_PER_BROKER", (
        f"independent read after UpdateMonitoring: expected PER_TOPIC_PER_BROKER, got {applied} "
        f"(baseline was {baseline})"
    )

    # --- negative: a stale CurrentVersion is rejected, and the value it targeted never lands ---
    stale_version = version  # the pre-update version -- now outdated on a real cluster
    stale_err = _err(
        lambda: msk.update_monitoring(
            ClusterArn=arn, CurrentVersion=stale_version, EnhancedMonitoring="PER_TOPIC_PER_PARTITION"
        )
    )
    assert stale_err == _STALE_VERSION, (
        f"stale CurrentVersion on a real cluster: expected {_STALE_VERSION!r}, got {stale_err!r}"
    )
    unmoved = _current_monitoring(msk, arn)
    assert unmoved == "PER_TOPIC_PER_BROKER", (
        f"a rejected UpdateMonitoring must not change state: expected PER_TOPIC_PER_BROKER, got {unmoved}"
    )

    # --- restore: the identical call with the *current* version now succeeds ---
    fresh_version = _current_version(msk, arn)
    resp2 = msk.update_monitoring(
        ClusterArn=arn, CurrentVersion=fresh_version, EnhancedMonitoring="PER_TOPIC_PER_PARTITION"
    )
    _wait_operation_complete(msk, resp2["ClusterOperationArn"])
    restored = _current_monitoring(msk, arn)
    assert restored == "PER_TOPIC_PER_PARTITION", (
        f"identical call with the correct version: expected PER_TOPIC_PER_PARTITION, got {restored}"
    )

    # --- negative: an unknown cluster is resolved (404) before any monitoring parameter is honoured ---
    ghost = _bogus_cluster_arn(ctx)

    err = _err(
        lambda: msk.update_monitoring(
            ClusterArn=ghost, CurrentVersion="1", EnhancedMonitoring="PER_TOPIC_PER_BROKER"
        )
    )
    assert err == _NOT_FOUND, f"expected {_NOT_FOUND!r}, got {err!r}"

    open_monitoring = _err(
        lambda: msk.update_monitoring(
            ClusterArn=ghost,
            CurrentVersion="1",
            EnhancedMonitoring="DEFAULT",
            OpenMonitoring={
                "Prometheus": {
                    "JmxExporter": {"EnabledInBroker": True},
                    "NodeExporter": {"EnabledInBroker": True},
                }
            },
        )
    )
    assert open_monitoring == _NOT_FOUND, (
        f"OpenMonitoring form: expected {_NOT_FOUND!r}, got {open_monitoring!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
