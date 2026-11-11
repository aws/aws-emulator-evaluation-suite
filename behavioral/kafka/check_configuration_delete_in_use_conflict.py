"""configuration-delete-in-use-conflict."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configuration-delete-in-use-conflict"
GROUP = 'configuration'
SERVICES = ['kafka']

_DEFAULT_KAFKA_VERSION = "3.9.x"
_PROVISIONED_INSTANCE_TYPE = "kafka.m5.large"


def _gone(fn) -> bool:
    """True once fn() raises NotFoundException, False while it succeeds; other errors raise."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NotFoundException":
            return True
        raise
    return False


def _expect_error(fn):
    """Call fn(); return the ClientError (code, message). An unexpected success raises, so acceptance is never
    reported as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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


def _wait_cluster_active(msk, arn, timeout_s=2700, interval_s=30):
    """Poll DescribeCluster (v1) until the cluster settles; Skip if it FAILED."""
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


def _wait_cluster_gone(msk, arn, timeout_s=1800, interval_s=30):
    return _poll_until(
        lambda: _gone(lambda: msk.describe_cluster(ClusterArn=arn)),
        lambda gone: gone,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"cluster {arn} to be deleted",
    )

def _wait_operation(msk, op_arn, timeout_s=1800, interval_s=15):
    return _poll_until(
        lambda: msk.describe_cluster_operation(ClusterOperationArn=op_arn)["ClusterOperationInfo"],
        lambda i: i.get("OperationState") in ("UPDATE_COMPLETE", "UPDATE_FAILED"),
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"cluster operation {op_arn} to settle",
    )


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteConfiguration rejects (BadRequestException) a configuration attached to a cluster,
    leaving it ACTIVE, while an unattached one deletes; once the cluster moves to another
    configuration the same delete succeeds.
    """
    msk = ctx.client("kafka")

    def _new_configuration(prefix):
        # MSK configurations are not taggable: CreateConfiguration has no Tags field, and
        # real AWS rejects TagResource on a configuration ARN with BadRequestException
        # ("Invalid input resource arn"), so cleanup is by direct id.
        name = ctx.unique_name(f"sim2real-behav-config-{prefix}-")
        cfg = msk.create_configuration(
            Name=name,
            ServerProperties=b"auto.create.topics.enable=true\n",
            KafkaVersions=["3.9.x"],
        )
        return cfg["Arn"]

    # Positive control: DeleteConfiguration on an unattached configuration succeeds. Without
    # this, "rejects the in-use configuration" is indistinguishable from "rejects every delete".
    control_arn = _new_configuration("pc")
    ctx.on_cleanup(lambda _a=control_arn: _delete_configuration_when_free(msk, _a))
    control_delete = msk.delete_configuration(Arn=control_arn)
    assert control_delete["Arn"] == control_arn, f"positive-control DeleteConfiguration answered {control_delete}"
    _wait_configuration_gone(msk, control_arn)

    config_arn = _new_configuration("inuse")
    ctx.on_cleanup(lambda _a=config_arn: _delete_configuration_when_free(msk, _a))
    restore_arn = _new_configuration("restore")
    ctx.on_cleanup(lambda _a=restore_arn: _delete_configuration_when_free(msk, _a))

    cluster_arn, _name, _subnets, _sg = _create_basic_cluster(ctx, msk, name_prefix="cfg-inuse-cluster-")
    info = _wait_cluster_active(msk, cluster_arn)

    op = msk.update_cluster_configuration(
        ClusterArn=cluster_arn,
        ConfigurationInfo={"Arn": config_arn, "Revision": 1},
        CurrentVersion=info["CurrentVersion"],
    )
    _wait_operation(msk, op["ClusterOperationArn"])
    info = _wait_cluster_active(msk, cluster_arn)

    code, message = _expect_error(lambda: msk.delete_configuration(Arn=config_arn))
    assert code == "BadRequestException", f"expected BadRequestException deleting in-use configuration, got {code!r}"
    assert message == (
        "Configuration is in use by one or more clusters. Dissociate the configuration from the clusters."
    ), f"in-use DeleteConfiguration message: {message!r}"

    # Independent read: the refused delete had no effect -- still ACTIVE.
    still_active = msk.describe_configuration(Arn=config_arn)
    assert still_active["State"] == "ACTIVE", (
        f"in-use configuration should remain ACTIVE after a refused delete, got {still_active.get('State')!r}"
    )

    op2 = msk.update_cluster_configuration(
        ClusterArn=cluster_arn,
        ConfigurationInfo={"Arn": restore_arn, "Revision": 1},
        CurrentVersion=info["CurrentVersion"],
    )
    _wait_operation(msk, op2["ClusterOperationArn"])
    _wait_cluster_active(msk, cluster_arn)

    freed_delete = msk.delete_configuration(Arn=config_arn)
    assert freed_delete["Arn"] == config_arn, f"freed DeleteConfiguration answered {freed_delete}"
    _wait_configuration_gone(msk, config_arn)


def _delete_configuration_when_free(msk, arn, timeout_s=1800.0, interval_s=30.0):
    """The cluster teardown only starts DeleteCluster, so the configuration stays in use until
    the cluster is gone; the check itself already deletes one of them."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            msk.delete_configuration(Arn=arn)
            return
        except ClientError as e:
            message = e.response["Error"].get("Message", "")
            if "does not exist" in message:
                return
            if "in use" not in message or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _wait_configuration_gone(msk, arn, timeout_s=120, interval_s=3):
    """Delete is asynchronous: DescribeConfiguration answers State DELETING until it refuses the ARN with
    BadRequestException "Configuration ARN does not exist."; any other answer fails at once."""

    def _probe():
        try:
            state = msk.describe_configuration(Arn=arn)["State"]
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code, message = err.get("Code"), err.get("Message")
            assert (code, message) == ("BadRequestException", "Configuration ARN does not exist."), (
                f"DescribeConfiguration after delete refused with {code!r}: {message!r}"
            )
            return "GONE"
        assert state == "DELETING", f"DescribeConfiguration after delete answered State {state!r}"
        return state

    _poll_until(_probe, lambda answer: answer == "GONE", timeout_s=timeout_s, interval_s=interval_s,
                description=f"configuration {arn} to be refused as deleted")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
