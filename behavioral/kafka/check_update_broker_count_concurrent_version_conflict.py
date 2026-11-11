"""update-broker-count-concurrent-version-conflict."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-broker-count-concurrent-version-conflict"
GROUP = 'cluster-state-guards'
SERVICES = ['kafka']

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


def _delete_cluster_when_settled(msk, arn, timeout_s=1200.0, interval_s=2.0):
    """DeleteCluster refuses a cluster that is CREATING or UPDATING, so wait for ACTIVE or FAILED,
    delete it, then wait until the cluster is gone."""
    deadline = time.monotonic() + timeout_s
    deleted = False
    while True:
        try:
            state = msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"]
            if state in ("ACTIVE", "FAILED") and not deleted:
                msk.delete_cluster(ClusterArn=arn)
                deleted = True
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {arn} still {state} after {timeout_s:.0f}s; it was not deleted")
        time.sleep(interval_s)


def _wait_cluster_active(ctx, msk, arn):
    """Wait until the cluster is ACTIVE and return its ClusterInfo. Real MSK provisioning takes
    ~20-30 minutes, so the deadline covers that; a target that is ACTIVE sooner ends the poll
    sooner."""
    budget_s = 1800
    interval_s = 2
    deadline = time.monotonic() + budget_s
    last = None
    while time.monotonic() < deadline:
        info = msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]
        last = info["State"]
        if last == "ACTIVE":
            return info
        if last == "FAILED":
            raise AssertionError("cluster reached FAILED instead of ACTIVE")
        time.sleep(interval_s)
    raise AssertionError(
        f"cluster not ACTIVE within {budget_s}s (last state {last}); "
        "MSK provisioning exceeds the per-check budget"
    )


def _run_concurrent(fns, *, timeout_s=60):
    """Run callables in parallel; return results in submission order (a raised exception is
    captured as its slot's value rather than propagating)."""
    import concurrent.futures

    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:  # noqa: BLE001 — captured for the caller to assert on
            results[idx] = exc
        resolved.add(idx)

    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


def _concurrent_error_codes(results):
    """Error codes for the _run_concurrent entries that raised (ClientError -> Error.Code,
    other exceptions -> class name); successes are skipped."""
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get("Error", {}).get("Code"))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateBrokerCount calls sharing one CurrentVersion: exactly one is accepted
    and starts a ClusterOperation that DescribeClusterOperation reads back, and the loser fails with
    BadRequestException "The version of the cluster isn't current. ...", so the version admits one scale."""
    msk = ctx.client("kafka")
    arn, _name, _subnets, _sg = _create_basic_cluster(ctx, msk, num_brokers=2, name_prefix="brokerrace-")
    info = _wait_cluster_active(ctx, msk, arn)
    version = info["CurrentVersion"]

    def racer(target):
        return lambda: msk.update_broker_count(
            ClusterArn=arn, CurrentVersion=version, TargetNumberOfBrokerNodes=target
        )

    results = _run_concurrent([racer(4), racer(6)])
    successes = [r for r in results if isinstance(r, dict)]
    errors = _concurrent_error_codes(results)

    assert len(successes) == 1, f"expected exactly one racer to win, got {len(successes)}"
    assert len(errors) == 1, f"expected exactly one racer to fail, got {errors}"
    assert errors[0] == "BadRequestException", f"losing racer must be BadRequestException, got {errors[0]}"
    messages = [r.response.get("Error", {}).get("Message") for r in results if isinstance(r, ClientError)]
    assert messages == ["The version of the cluster isn\u2019t current. Check the current version and try again."], (
        f"losing racer's message: {messages}"
    )

    # Independent reads at the destination: the winning racer's ClusterOperation must be a
    # real, externally-visible operation, and the cluster's own version must have moved past
    # the shared CurrentVersion the racers raced on (never both left the version untouched).
    op_arn = successes[0]["ClusterOperationArn"]
    op = msk.describe_cluster_operation(ClusterOperationArn=op_arn)["ClusterOperationInfo"]
    assert op["OperationArn"] == op_arn, (
        f"winning racer's ClusterOperation must be visible via an independent read, got {op}"
    )

    final_version = msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["CurrentVersion"]
    assert final_version != version, (
        f"cluster CurrentVersion must advance once a scale operation is accepted, "
        f"still {final_version}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
