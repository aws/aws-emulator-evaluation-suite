"""serverless-v2-scaling-bounds-echoed-and-inverted-range-refused."""
from __future__ import annotations

import secrets
import time

from botocore.exceptions import ClientError
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "serverless-v2-scaling-bounds-echoed-and-inverted-range-refused"
GROUP = "server-side"
SERVICES = ["rds"]

_INITIAL = {"MinCapacity": 0.5, "MaxCapacity": 1.0}
_RAISED = {"MinCapacity": 1.0, "MaxCapacity": 2.0}
_INVERTED_MESSAGE = (
    "Serverless v2 minimum capacity must be less than or equal to maximum capacity"
)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """An Aurora Serverless v2 cluster with a writer echoes its Min/MaxCapacity exactly from
    CreateDBCluster and DescribeDBClusters; an inverted range is refused with InvalidParameterValue
    and changes nothing, and ModifyDBCluster raising both bounds reads back exactly.

    Reference: https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ServerlessV2ScalingConfiguration.html
    """
    rds = ctx.client("rds")

    cluster_id = ctx.unique_name("sim2real-rds-sv2-")
    instance_id = ctx.unique_name("sim2real-rds-sv2i-")
    password = _rds_password()
    resource_tags = [{"Key": "sim2real-check", "Value": CHECK}]

    teardown: dict = {}
    subnet_group = _network_db_subnet_group(ctx, rds, teardown)
    created = rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-postgresql",
        MasterUsername="s2rtest",
        MasterUserPassword=password,
        ServerlessV2ScalingConfiguration=dict(_INITIAL),
        Tags=resource_tags,
        DBSubnetGroupName=subnet_group,
    )["DBCluster"]
    ctx.on_cleanup(lambda: _delete_cluster(rds, cluster_id, teardown))
    assert created.get("ServerlessV2ScalingConfiguration") == _INITIAL, (
        f"CreateDBCluster echoes {created.get('ServerlessV2ScalingConfiguration')!r}, expected "
        f"exactly {_INITIAL!r}"
    )

    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        DBInstanceClass="db.serverless",
        Engine="aurora-postgresql",
        DBClusterIdentifier=cluster_id,
        Tags=resource_tags,
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, instance_id, teardown))

    _wait_for_instance_status(rds, instance_id, "available", timeout_s=1500)
    cluster = _wait_for_cluster_status(rds, cluster_id, "available", timeout_s=600)
    assert cluster["ServerlessV2ScalingConfiguration"] == _INITIAL, (
        f"expected ServerlessV2ScalingConfiguration exactly {_INITIAL!r}, got "
        f"{cluster['ServerlessV2ScalingConfiguration']!r}"
    )

    error = _client_error(lambda: rds.modify_db_cluster(
        DBClusterIdentifier=cluster_id,
        ApplyImmediately=True,
        ServerlessV2ScalingConfiguration={"MinCapacity": 2.0, "MaxCapacity": 1.0},
    ))
    assert error.get("Code") == "InvalidParameterValue", (
        f"a MaxCapacity below MinCapacity must be refused InvalidParameterValue, got {error!r}"
    )
    assert error.get("Message") == _INVERTED_MESSAGE, (
        f"expected the message {_INVERTED_MESSAGE!r}, got {error.get('Message')!r}"
    )
    still = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    assert still["ServerlessV2ScalingConfiguration"] == _INITIAL, (
        f"the refused modify must leave the range at {_INITIAL!r}; it reads "
        f"{still['ServerlessV2ScalingConfiguration']!r}"
    )

    # Raise both bounds; DescribeDBClusters reports the new range once the modify applies.
    rds.modify_db_cluster(
        DBClusterIdentifier=cluster_id,
        ServerlessV2ScalingConfiguration=dict(_RAISED),
        ApplyImmediately=True,
    )
    raised = _poll_until(
        lambda: rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0],
        lambda c: c["Status"] == "available" and c["ServerlessV2ScalingConfiguration"] == _RAISED,
        timeout_s=600, interval_s=2,
    )
    assert raised["ServerlessV2ScalingConfiguration"] == _RAISED, (
        f"expected raised ServerlessV2ScalingConfiguration exactly {_RAISED!r}, got "
        f"{raised['ServerlessV2ScalingConfiguration']!r} (status {raised['Status']!r})"
    )


def _rds_password() -> str:
    return "S2r" + secrets.token_hex(8)


def _client_error(fn) -> dict:
    """The botocore Error dict (Code, Message) fn() raised; an accepted call fails the check."""
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"the call was ACCEPTED and returned "
        f"{ {k: v for k, v in resp.items() if k != 'ResponseMetadata'} !r}"
    )


def _wait_for_instance_status(rds: Any, instance_id: str, status: str, *, timeout_s: float) -> dict:
    def _probe() -> dict:
        return rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]

    result = _poll_until(
        _probe, lambda inst: inst["DBInstanceStatus"] == status, timeout_s=timeout_s, interval_s=5
    )
    if result["DBInstanceStatus"] != status:
        raise AssertionError(
            f"instance {instance_id} never reached status {status!r} "
            f"(last: {result['DBInstanceStatus']!r})"
        )
    return result


def _wait_for_cluster_status(rds: Any, cluster_id: str, status: str, *, timeout_s: float) -> dict:
    def _probe() -> dict:
        return rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]

    result = _poll_until(
        _probe, lambda c: c["Status"] == status, timeout_s=timeout_s, interval_s=5
    )
    if result["Status"] != status:
        raise AssertionError(
            f"cluster {cluster_id} never reached status {status!r} (last: {result['Status']!r})"
        )
    return result


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
) -> Any:
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            return value
        time.sleep(interval_s)
        value = probe()
    return value


def _teardown_deadline(teardown):
    """The run's one teardown deadline, started by the first delete."""
    if "deadline" not in teardown:
        teardown["deadline"] = time.monotonic() + 1740.0
    return teardown["deadline"]


def _delete_when_released(delete, busy_codes, gone_codes, teardown, interval_s=2.0):
    """Delete, retrying while a dependent resource still holds it; gone counts as done."""
    deadline = _teardown_deadline(teardown)
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _gone(describe, gone_code, teardown, what):
    """Wait until describe() raises gone_code; a survivor at the deadline raises."""
    deadline = _teardown_deadline(teardown)
    while True:
        try:
            describe()
        except ClientError as e:
            if e.response["Error"]["Code"] == gone_code:
                return
            raise
        if time.monotonic() >= deadline:
            raise RuntimeError(f"{what} still exists at the teardown deadline")
        time.sleep(2)


def _delete_instance(rds, instance_id, teardown):
    """Delete the writer and wait until it is gone; the cluster refuses delete while it remains."""
    _delete_when_released(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True),
        ("InvalidDBInstanceState",), ("DBInstanceNotFound",), teardown,
    )
    _gone(lambda: rds.describe_db_instances(DBInstanceIdentifier=instance_id),
          "DBInstanceNotFound", teardown, f"instance {instance_id}")


def _delete_cluster(rds, cluster_id, teardown):
    """Delete the cluster with no final snapshot and wait until it is gone, so its subnet group
    is released."""
    _delete_when_released(
        lambda: rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True),
        ("InvalidDBClusterStateFault",), ("DBClusterNotFoundFault",), teardown,
    )
    _gone(lambda: rds.describe_db_clusters(DBClusterIdentifier=cluster_id),
          "DBClusterNotFoundFault", teardown, f"cluster {cluster_id}")


def _network_db_subnet_group(ctx, client, teardown) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_db_subnet_group(DBSubnetGroupName=name),
            ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
            ("DBSubnetGroupNotFoundFault",),
            teardown,
        )
    )
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
