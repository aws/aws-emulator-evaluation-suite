"""modify-instance-engine-family-change-rejected."""
from __future__ import annotations

import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-instance-engine-family-change-rejected"
GROUP = "overly-permissive"
SERVICES = ["rds"]

_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-rds-engfam-"},
    {"Key": "sim2real", "Value": "modify-instance-engine-family-change-rejected"},
]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyDBInstance with Engine=postgres on a mysql instance is rejected with
    InvalidParameterCombination and its exact message and the engine stays mysql, while a
    CopyTagsToSnapshot=True modify of the same instance takes effect."""
    rds = ctx.client("rds")
    db_id = ctx.unique_name("sim2real-rds-engfam-")
    password = "S2r" + secrets.token_hex(10)

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        Engine="mysql",
        DBInstanceClass="db.t3.micro",
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        AllocatedStorage=20,
        BackupRetentionPeriod=1,
        PubliclyAccessible=False,
        Tags=_TAGS,
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _safe_delete_instance(ctx, db_id))

    _poll_until(
        lambda: _describe_instance(rds, db_id),
        lambda inst: inst is not None and inst["DBInstanceStatus"] == "available",
        timeout_s=1200,
        interval_s=20,
    )

    # Break exactly one thing: ask ModifyDBInstance to convert this mysql instance's Engine to
    # postgres -- not one of the two values (oracle-ee-cdb|oracle-se2-cdb) this parameter accepts,
    # and meaningless for a non-Oracle instance either way.
    code, message = _error(
        lambda: rds.modify_db_instance(
            DBInstanceIdentifier=db_id, Engine="postgres", ApplyImmediately=True
        )
    )
    assert code == "InvalidParameterCombination", f"expected InvalidParameterCombination, got {code!r}"
    expected = "Modification of database from engine mysql to engine postgres is not supported."
    assert message == expected, f"unexpected error message: {message!r} != {expected!r}"

    # Effect absent: the instance's engine must still be mysql, not silently switched.
    inst = _describe_instance(rds, db_id)
    assert inst is not None and inst["Engine"] == "mysql", (
        f"engine family was not supposed to change, observed Engine={inst and inst.get('Engine')!r}"
    )

    # Positive control: a legitimate, engine-agnostic ModifyDBInstance change on the very same
    # instance must still succeed and take effect.
    rds.modify_db_instance(DBInstanceIdentifier=db_id, CopyTagsToSnapshot=True, ApplyImmediately=True)
    updated = _poll_until(
        lambda: _describe_instance(rds, db_id),
        lambda inst: inst is not None and inst.get("CopyTagsToSnapshot") is True,
        timeout_s=120,
        interval_s=5,
    )
    assert updated["CopyTagsToSnapshot"] is True, (
        f"positive control ModifyDBInstance(CopyTagsToSnapshot=True) did not take effect, "
        f"observed CopyTagsToSnapshot={updated.get('CopyTagsToSnapshot')!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected ModifyDBInstance to be rejected, but it SUCCEEDED and returned {result!r}")


def _describe_instance(rds, db_id):
    try:
        return rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "DBInstanceNotFound":
            return None
        raise


def _poll_until(probe, predicate, *, timeout_s=900, interval_s=15):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {last!r}")


def _safe_delete_instance(ctx, db_id) -> None:
    rds = ctx.client("rds")
    try:
        rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBInstanceNotFound":
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
