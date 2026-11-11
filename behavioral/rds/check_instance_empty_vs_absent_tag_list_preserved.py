"""instance-empty-vs-absent-tag-list-preserved."""
from __future__ import annotations

import secrets
import string
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "instance-empty-vs-absent-tag-list-preserved"
GROUP = "representation"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Instances created with Tags=[] and with Tags omitted both read back an empty TagList from
    DescribeDBInstances: neither path adds a tag."""
    rds = ctx.client("rds")

    password = _random_password()
    id_explicit_empty = ctx.unique_name("sim2real-tagempty-")
    id_omitted = ctx.unique_name("sim2real-tagabsent-")

    base_kwargs = dict(
        Engine="mysql",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        BackupRetentionPeriod=1,
        PubliclyAccessible=False,
    )

    rds.create_db_instance(DBInstanceIdentifier=id_explicit_empty, Tags=[], DBSubnetGroupName=_network_db_subnet_group(ctx, rds), **base_kwargs)
    rds.create_db_instance(DBInstanceIdentifier=id_omitted, DBSubnetGroupName=_network_db_subnet_group(ctx, rds), **base_kwargs)
    ctx.on_cleanup(lambda: _wait_available_and_delete(rds, [id_explicit_empty, id_omitted]))

    desc_empty = rds.describe_db_instances(DBInstanceIdentifier=id_explicit_empty)[
        "DBInstances"
    ][0]
    desc_omitted = rds.describe_db_instances(DBInstanceIdentifier=id_omitted)["DBInstances"][0]

    tags_empty = desc_empty.get("TagList", [])
    tags_omitted = desc_omitted.get("TagList", [])

    assert tags_empty == [], f"explicit Tags=[] instance came back with phantom tags: {tags_empty!r}"
    assert tags_omitted == [], (
        f"Tags-omitted instance came back with phantom tags: {tags_omitted!r}"
    )
    assert tags_empty == tags_omitted, (
        "explicit-empty and omitted Tags produced different TagList representations: "
        f"{tags_empty!r} vs {tags_omitted!r}"
    )


def _random_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(20))


def _wait_available_and_delete(rds, instance_ids: list[str]) -> None:
    def _one(instance_id: str) -> None:
        rds.get_waiter("db_instance_available").wait(
            DBInstanceIdentifier=instance_id,
            WaiterConfig={"Delay": 2, "MaxAttempts": 900},
        )
        rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)

    with ThreadPoolExecutor(max_workers=len(instance_ids)) as pool:
        list(pool.map(_one, instance_ids))


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
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
