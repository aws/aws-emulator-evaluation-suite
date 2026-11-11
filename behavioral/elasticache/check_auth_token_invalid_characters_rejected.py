"""auth-token-invalid-characters-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "auth-token-invalid-characters-rejected"
GROUP = "server-side"
SERVICES = ["elasticache"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateReplicationGroup rejects an AuthToken with a character outside !&#$^<>-
    and alphanumerics as InvalidParameterValue and creates nothing, while the same
    request with only allowed characters provisions (positive control)."""
    ec = ctx.client("elasticache")
    vpc_id = _default_vpc_id(ctx)
    subnet_ids = _subnet_ids(ctx, vpc_id, count=2)
    subnet_group_name = _create_subnet_group(ctx, subnet_ids)

    rejected_id = ctx.unique_name("sim2real-authbad-")
    invalid_token = "Aa1@34567890ABCD"  # '@' is explicitly disallowed
    code, message = _error(
        lambda: ec.create_replication_group(
            ReplicationGroupId=rejected_id,
            ReplicationGroupDescription="sim2real invalid auth token check",
            Engine="redis",
            CacheNodeType="cache.t3.micro",
            NumCacheClusters=1,
            CacheSubnetGroupName=subnet_group_name,
            TransitEncryptionEnabled=True,
            TransitEncryptionMode="required",
            AutomaticFailoverEnabled=False,
            AuthToken=invalid_token,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )
    assert code == "InvalidParameterValue", f"unexpected error code {code!r}"
    assert message == "Invalid AuthToken provided.", f"unexpected InvalidParameterValue message: {message!r}"

    # Effect absent: the rejected id must never have been created.
    not_found_code, not_found_message = _error(
        lambda: ec.describe_replication_groups(ReplicationGroupId=rejected_id)
    )
    assert not_found_code == "ReplicationGroupNotFoundFault", (
        f"expected no replication group to exist for the rejected id, got code {not_found_code!r}"
    )
    expected_not_found = f"ReplicationGroup {rejected_id} not found."
    assert not_found_message == expected_not_found, (
        f"expected message {expected_not_found!r}, got {not_found_message!r}"
    )

    # Positive control: an otherwise-identical request with only allowed characters succeeds.
    accepted_id = ctx.unique_name("sim2real-authok-")
    valid_token = "Aa1!&#$^<>-Bb2Cc3"
    ec.create_replication_group(
        ReplicationGroupId=accepted_id,
        ReplicationGroupDescription="sim2real valid auth token check",
        Engine="redis",
        CacheNodeType="cache.t3.micro",
        NumCacheClusters=1,
        CacheSubnetGroupName=subnet_group_name,
        TransitEncryptionEnabled=True,
        TransitEncryptionMode="required",
        AutomaticFailoverEnabled=False,
        AuthToken=valid_token,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_replication_group(ec, accepted_id))
    final_status = _wait_for_status(ec, accepted_id, {"available"}, timeout_s=1200)
    assert final_status == "available", (
        f"expected positive-control replication group {accepted_id} to reach 'available' "
        f"using only allowed AuthToken characters, got status {final_status!r}"
    )


# ===== helpers =====
def _default_vpc_id(ctx: Any) -> str:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    return vpcs[0]["VpcId"]


def _subnet_ids(ctx: Any, vpc_id: str, count: int = 2) -> list[str]:
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if len(subnets) < count:
        raise AssertionError(f"fewer than {count} subnets available in VPC {vpc_id}")
    return [s["SubnetId"] for s in subnets[:count]]


def _create_subnet_group(ctx: Any, subnet_ids: list[str]) -> str:
    ec = ctx.client("elasticache")
    name = ctx.unique_name("sim2real-authtok-subnetgrp-")
    ec.create_cache_subnet_group(
        CacheSubnetGroupName=name, CacheSubnetGroupDescription="sim2real behavioral", SubnetIds=subnet_ids
    )
    ctx.on_cleanup(lambda: ec.delete_cache_subnet_group(CacheSubnetGroupName=name))
    return name


def _error(fn):
    """Call fn(); return (code, message) from the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses fails loudly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED with {result!r}")


def _wait_for_status(ec: Any, rg_id: str, targets: set, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = ec.describe_replication_groups(ReplicationGroupId=rg_id)
        last = resp["ReplicationGroups"][0]["Status"]
        if last in targets:
            return last
        time.sleep(2)
    raise AssertionError(f"replication group {rg_id} never reached {targets}; last={last}")


def _delete_replication_group(ec: Any, rg_id: str) -> None:
    """Delete rg_id and wait until it is gone; a group still creating is retried."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 900
    while True:
        try:
            ec.delete_replication_group(ReplicationGroupId=rg_id)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ReplicationGroupNotFoundFault":
                return
            if code != "InvalidReplicationGroupState" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while time.monotonic() < deadline:
        try:
            ec.describe_replication_groups(ReplicationGroupId=rg_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ReplicationGroupNotFoundFault":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"replication group {rg_id} was not deleted within 900 s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
