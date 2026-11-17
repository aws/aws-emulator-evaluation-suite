"""create-replication-group-invalid-replication-group-id-rejected."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-replication-group-invalid-replication-group-id-rejected"
GROUP = "negative-classes"
SERVICES = ["elasticache"]

_FORMAT_MESSAGE = (
    "Replication Group ID specified is not a valid identifier. Identifiers must begin with "
    "a letter; must contain only ASCII letters, digits, and hyphens; and must not end with "
    "a hyphen or contain two consecutive hyphens."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateReplicationGroup with a ReplicationGroupId that starts with a digit, or that
    ends with a hyphen, is rejected with InvalidParameterValue and its exact message and
    creates no group, while the same characters rearranged into a valid id succeed."""
    ec = ctx.client("elasticache")
    suffix = ctx.unique_name("ercg").replace("-", "")[:16]
    subnet_group = _network_cache_subnet_group(ctx, ec)

    digit_leading_id = f"9{suffix}"
    code, message = _error(
        lambda: ec.create_replication_group(
            ReplicationGroupId=digit_leading_id,
            ReplicationGroupDescription="sim2real behavioral invalid-id probe",
            Engine="redis",
            CacheNodeType="cache.t3.micro",
            NumCacheClusters=1,
            CacheSubnetGroupName=subnet_group,
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    assert message == _FORMAT_MESSAGE, f"unexpected message for a digit-leading id: {message!r}"

    # Describe also validates the id's format before it ever looks the group up, so the
    # malformed id is refused there too, with the same format message as Create.
    describe_code, describe_message = _error(
        lambda: ec.describe_replication_groups(ReplicationGroupId=digit_leading_id)
    )
    assert describe_code == "InvalidParameterValue", (
        f"expected InvalidParameterValue, got {describe_code!r}"
    )
    assert describe_message == _FORMAT_MESSAGE, (
        f"unexpected Describe message for a digit-leading id: {describe_message!r}"
    )

    trailing_hyphen_id = f"r{suffix}-"
    code, message = _error(
        lambda: ec.create_replication_group(
            ReplicationGroupId=trailing_hyphen_id,
            ReplicationGroupDescription="sim2real behavioral invalid-id probe",
            Engine="redis",
            CacheNodeType="cache.t3.micro",
            NumCacheClusters=1,
            CacheSubnetGroupName=subnet_group,
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    assert message == _FORMAT_MESSAGE, f"unexpected message for a trailing-hyphen id: {message!r}"

    describe_code, describe_message = _error(
        lambda: ec.describe_replication_groups(ReplicationGroupId=trailing_hyphen_id)
    )
    assert describe_code == "InvalidParameterValue", (
        f"expected InvalidParameterValue, got {describe_code!r}"
    )
    assert describe_message == _FORMAT_MESSAGE, (
        f"unexpected Describe message for a trailing-hyphen id: {describe_message!r}"
    )

    # Positive control: the same characters, letter-led with no trailing hyphen, are a
    # valid id and bring up a real replication group.
    valid_id = f"r{suffix}"
    ec.create_replication_group(
        ReplicationGroupId=valid_id,
        ReplicationGroupDescription="sim2real behavioral invalid-id probe",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheClusters=1,
        CacheSubnetGroupName=subnet_group,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _best_effort_delete(ec, valid_id))
    group = _wait_for_status(ec, valid_id, {"available"}, timeout_s=900.0)
    assert group["ReplicationGroupId"] == valid_id, group


def _wait_for_status(ec, replication_group_id, targets, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        groups = ec.describe_replication_groups(
            ReplicationGroupId=replication_group_id
        )["ReplicationGroups"]
        if groups:
            last = groups[0]["Status"]
            if last in targets:
                return groups[0]
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"replication group {replication_group_id} never reached {targets}, last status={last!r}"
            )
        time.sleep(interval_s)


def _best_effort_delete(ec, replication_group_id):
    try:
        ec.delete_replication_group(ReplicationGroupId=replication_group_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ReplicationGroupNotFoundFault":
            raise


def _network_cache_subnet_group(ctx, client) -> str:
    """A subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-ercg-net-")
    client.create_cache_subnet_group(
        CacheSubnetGroupName=name,
        CacheSubnetGroupDescription="sim2real behavioral shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_subnet_group_when_released(
            lambda: client.delete_cache_subnet_group(CacheSubnetGroupName=name),
        )
    )
    return name


def _delete_subnet_group_when_released(delete, timeout_s=1200.0, interval_s=15.0):
    """Delete the subnet group, retrying while a replication group being torn down still
    holds it; CacheSubnetGroupInUse means the dependent delete has not finished yet."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "CacheSubnetGroupNotFoundFault":
                return
            if code != "CacheSubnetGroupInUse" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _error(fn: Any) -> tuple[str, str]:
    """Call fn(); return the botocore Error (Code, Message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected a ClientError but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
