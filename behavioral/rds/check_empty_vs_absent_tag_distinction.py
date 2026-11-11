"""empty-vs-absent-tag-distinction."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "empty-vs-absent-tag-distinction"
GROUP = "representation"
SERVICES = ["rds"]

_MASTER_USER = "sim2realadmin"
_MASTER_PASS = "Sim2RealPwd123"
_EMPTY_KEY = "sim2real-empty-value"
_NEVER_ADDED_KEY = "sim2real-never-added"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """A tag whose VALUE is an empty string is a distinct, present entry in
    ListTagsForResource -- not indistinguishable from a key that was never added, and not
    indistinguishable from a key that was added and then removed."""
    rds = ctx.client("rds")
    db_id = ctx.unique_name("sim2real-tagempty-")

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername=_MASTER_USER,
        MasterUserPassword=_MASTER_PASS,
        AllocatedStorage=20,
        BackupRetentionPeriod=0,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, db_id))
    inst = _wait_for_instance_status(rds, db_id, "available", timeout_s=900)
    arn = inst["DBInstanceArn"]

    # Baseline: neither key exists yet.
    baseline = rds.list_tags_for_resource(ResourceName=arn)["TagList"]
    assert not any(t["Key"] == _EMPTY_KEY for t in baseline), (
        f"fresh instance unexpectedly already carries tag key {_EMPTY_KEY!r}: {baseline!r}"
    )
    assert not any(t["Key"] == _NEVER_ADDED_KEY for t in baseline), (
        f"fresh instance unexpectedly already carries tag key {_NEVER_ADDED_KEY!r}: {baseline!r}"
    )

    rds.add_tags_to_resource(ResourceName=arn, Tags=[{"Key": _EMPTY_KEY, "Value": ""}])

    after_add = rds.list_tags_for_resource(ResourceName=arn)["TagList"]
    empty_tag = next((t for t in after_add if t["Key"] == _EMPTY_KEY), None)
    assert empty_tag is not None, "tag key set to an empty string value was not stored at all"
    assert empty_tag["Value"] == "", f"expected empty string tag value, got {empty_tag['Value']!r}"
    # The never-added key remains genuinely absent, not conflated with the empty-value tag.
    assert not any(t["Key"] == _NEVER_ADDED_KEY for t in after_add), (
        "a key that was never added appeared in the tag list"
    )

    rds.remove_tags_from_resource(ResourceName=arn, TagKeys=[_EMPTY_KEY])

    after_remove = rds.list_tags_for_resource(ResourceName=arn)["TagList"]
    assert not any(t["Key"] == _EMPTY_KEY for t in after_remove), (
        "removed tag key is still present after RemoveTagsFromResource"
    )


def _describe_instance(rds: Any, db_id: str) -> dict[str, Any]:
    return rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]


def _wait_for_instance_status(rds: Any, db_id: str, status: str, *, timeout_s: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        inst = _describe_instance(rds, db_id)
        if inst["DBInstanceStatus"] == status:
            return inst
        time.sleep(2)
    raise AssertionError(f"DB instance {db_id} never reached status={status!r} in {timeout_s}s")


def _delete_instance(rds: Any, db_id: str) -> None:
    try:
        rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBInstanceNotFoundFault":
            raise


def _network_db_subnet_group(ctx, client) -> str:
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
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
