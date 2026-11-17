"""deploy-global-replication-group-cfn-retains-primary-on-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-global-replication-group-cfn-retains-primary-on-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "elasticache"]

_SETTLING = frozenset({"creating", "modifying"})


_GRG_GONE = ("GlobalReplicationGroupNotFoundFault", "Global Replication Group not found")


def expect_error(fn, code: str, message: str) -> None:
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        got = (err.get("Code"), err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


def _template(suffix: str, description: str, primary_id: str, region: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "GlobalRepGroup": {
                "Type": "AWS::ElastiCache::GlobalReplicationGroup",
                "Properties": {
                    "GlobalReplicationGroupIdSuffix": suffix,
                    "GlobalReplicationGroupDescription": description,
                    "Members": [
                        {
                            "ReplicationGroupId": primary_id,
                            "ReplicationGroupRegion": region,
                            "Role": "PRIMARY",
                        }
                    ],
                },
            }
        },
        "Outputs": {"GlobalRepGroupRef": {"Value": {"Ref": "GlobalRepGroup"}}},
    })


def _wait_rg_available(ec, rg_id: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = ec.describe_replication_groups(ReplicationGroupId=rg_id)["ReplicationGroups"][0]["Status"]
        if status == "available":
            return
        time.sleep(2)
    raise AssertionError(f"replication group {rg_id} never reached available, last status={status!r}")


def _wait_stack(cfn, stack_id: str, terminal: set, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if "IN_PROGRESS" not in status:
            raise AssertionError(f"stack {stack_id} reached {status!r}, never {terminal!r}")
        time.sleep(2)
    raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")


def _wait_grg_settled(ec, global_id: str, timeout_s: float) -> str:
    """Poll past the ``Creating``/``Modifying`` transition; return the terminal status."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = ec.describe_global_replication_groups(GlobalReplicationGroupId=global_id)[
            "GlobalReplicationGroups"
        ][0]["Status"]
        if status not in _SETTLING:
            return status
        time.sleep(2)
    raise AssertionError(f"global replication group {global_id} still {status!r} after {timeout_s:.0f}s")


def _delete_replication_group(ec, rg_id: str, timeout_s: float = 900.0) -> None:
    try:
        ec.delete_replication_group(ReplicationGroupId=rg_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ReplicationGroupNotFoundFault":
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            ec.describe_replication_groups(ReplicationGroupId=rg_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ReplicationGroupNotFoundFault":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"replication group {rg_id} did not finish deleting within {timeout_s:.0f}s")


def _delete_stack(cfn, stack_id: str) -> None:
    try:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ValidationError":
            return
        raise
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    _wait_stack(cfn, stack_id, {"DELETE_COMPLETE"}, 900.0)


def _delete_subnet_group(ec, name: str, timeout_s: float = 300.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec.delete_cache_subnet_group(CacheSubnetGroupName=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "CacheSubnetGroupNotFoundFault":
                return
            if code != "CacheSubnetGroupInUse" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation GlobalReplicationGroup wraps an existing ReplicationGroup as its primary,
    round-trips a description update in place, and deleting the stack leaves that replication
    group behind while the Global Datastore itself is gone."""
    cfn = ctx.client("cloudformation")
    ec = ctx.client("elasticache")
    net = ctx.network()

    subnet_group_name = ctx.unique_name("sim2real-ecgrg-sng-")
    ec.create_cache_subnet_group(
        CacheSubnetGroupName=subnet_group_name,
        CacheSubnetGroupDescription=f"sim2real subnet group for {subnet_group_name}",
        SubnetIds=sorted(net.subnet_ids[:2]),
    )
    ctx.on_cleanup(lambda: _delete_subnet_group(ec, subnet_group_name))

    primary_id = ctx.unique_name("sim2real-ecgrg-primary-")
    ec.create_replication_group(
        ReplicationGroupId=primary_id,
        ReplicationGroupDescription=f"sim2real global datastore primary for {primary_id}",
        Engine="redis",
        EngineVersion="7.1",
        # Global Datastore supports only M-family/R-family large-and-above node types.
        CacheNodeType="cache.m5.large",
        NumCacheClusters=1,
        AutomaticFailoverEnabled=False,
        CacheSubnetGroupName=subnet_group_name,
        Tags=[{"Key": "sim2real", "Value": primary_id}],
    )
    ctx.on_cleanup(lambda: _delete_replication_group(ec, primary_id))
    _wait_rg_available(ec, primary_id, timeout_s=900.0)

    suffix = ctx.unique_name("sim2realecgrgsfx").replace("-", "")[:16]
    description_1 = f"sim2real global datastore wrapping {primary_id}"
    stack_name = ctx.unique_name("sim2real-ecgrg-stack-")
    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(suffix, description_1, primary_id, ctx.region),
        Tags=[{"Key": "sim2real", "Value": stack_name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    status = _wait_stack(cfn, stack_id, {"CREATE_COMPLETE", "ROLLBACK_COMPLETE"}, 1200.0)
    assert status == "CREATE_COMPLETE", f"stack {stack_id} ended {status!r}, expected CREATE_COMPLETE"

    global_id = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"][0]["OutputValue"]
    assert global_id.endswith(suffix), f"Ref {global_id!r} does not end with suffix {suffix!r}"

    settled = _wait_grg_settled(ec, global_id, timeout_s=600.0)
    assert settled == "primary-only", f"expected primary-only with no secondary, got {settled!r}"

    grg = ec.describe_global_replication_groups(GlobalReplicationGroupId=global_id, ShowMemberInfo=True)[
        "GlobalReplicationGroups"
    ][0]
    assert grg["GlobalReplicationGroupDescription"] == description_1, (
        f"description {grg['GlobalReplicationGroupDescription']!r} != {description_1!r}"
    )
    members = grg["Members"]
    assert len(members) == 1, f"expected exactly one member, got {members!r}"
    assert members[0]["ReplicationGroupId"] == primary_id, (
        f"member {members[0]['ReplicationGroupId']!r} != primary {primary_id!r}"
    )
    assert members[0]["Role"] == "PRIMARY", f"expected PRIMARY, got {members[0]['Role']!r}"

    description_2 = f"sim2real global datastore wrapping {primary_id}, renamed"
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(suffix, description_2, primary_id, ctx.region))
    status = _wait_stack(cfn, stack_id, {"UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"}, 600.0)
    assert status == "UPDATE_COMPLETE", f"stack update ended {status!r}, expected UPDATE_COMPLETE"

    updated_id = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"][0]["OutputValue"]
    assert updated_id == global_id, f"update replaced {global_id!r} with {updated_id!r}, expected in-place"
    grg = ec.describe_global_replication_groups(GlobalReplicationGroupId=global_id)["GlobalReplicationGroups"][0]
    assert grg["GlobalReplicationGroupDescription"] == description_2, (
        f"description after update {grg['GlobalReplicationGroupDescription']!r} != {description_2!r}"
    )

    _delete_stack(cfn, stack_id)
    expect_error(
        lambda: ec.describe_global_replication_groups(GlobalReplicationGroupId=global_id), *_GRG_GONE
    )
    expect_error(
        lambda: ec.modify_global_replication_group(
            GlobalReplicationGroupId=global_id, ApplyImmediately=True, GlobalReplicationGroupDescription="x"
        ),
        *_GRG_GONE,
    )

    primary = ec.describe_replication_groups(ReplicationGroupId=primary_id)["ReplicationGroups"][0]
    assert primary["Status"] == "available", (
        f"deleting the Global Datastore's stack should leave its primary behind, got {primary['Status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
