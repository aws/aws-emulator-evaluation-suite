"""db-instance-refuses-operations-while-creating."""
from __future__ import annotations

import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "db-instance-refuses-operations-while-creating"
GROUP = "state-machine"
SERVICES = ["rds"]

#: The code ``_outcome`` reports for a call the target accepted.
_ACCEPTED = "<accepted>"

#: Fresh instances tried before the check gives up on observing the creating window.
_ATTEMPTS = 3
_TAGS = [{"Key": "sim2real", "Value": CHECK}]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An instance still creating refuses ModifyDBInstance, StopDBInstance and CreateDBSnapshot with
    InvalidDBInstanceState, answers its log-file calls with DBInstanceNotFound, and refuses a
    point-in-time restore with PointInTimeRestoreNotEnabled, each with its exact message."""
    rds = ctx.client("rds")
    subnet_group = _subnet_group(ctx, rds)
    legs = {
        "ModifyDBInstance": (
            lambda i: rds.modify_db_instance(DBInstanceIdentifier=i, DBInstanceClass="db.t3.micro",
                                             ApplyImmediately=True),
            "InvalidDBInstanceState", "Database instance is not in available state."),
        "StopDBInstance": (
            lambda i: rds.stop_db_instance(DBInstanceIdentifier=i),
            "InvalidDBInstanceState", "Instance {i} is not in available state."),
        "DescribeDBLogFiles": (
            lambda i: rds.describe_db_log_files(DBInstanceIdentifier=i),
            "DBInstanceNotFound", "DBInstance {i} not found."),
        "DownloadDBLogFilePortion": (
            lambda i: rds.download_db_log_file_portion(
                DBInstanceIdentifier=i, LogFileName="error/mysql-error.log", NumberOfLines=10),
            "DBInstanceNotFound", "DBInstance {i} not found."),
        "CreateDBSnapshot": (
            lambda i: _snapshot(ctx, rds, i),
            "InvalidDBInstanceState",
            "Cannot create a snapshot because the database instance {i} is not currently in the "
            "available state."),
        "RestoreDBInstanceToPointInTime": (
            lambda i: _restore(ctx, rds, i, subnet_group),
            "PointInTimeRestoreNotEnabled",
            "The backup retention period is set to 1, but no backups are available yet. Most likely "
            "this is because backup retention has only recently been changed from zero to a non-zero "
            "value."),
    }
    pending = list(legs)
    tried = []
    for _ in range(_ATTEMPTS):
        if not pending:
            break
        instance = ctx.unique_name("sim2real-rds-icr-")
        created = rds.create_db_instance(
            DBInstanceIdentifier=instance, DBInstanceClass="db.t3.micro", Engine="mysql",
            MasterUsername="admin", MasterUserPassword=_password(), AllocatedStorage=20,
            BackupRetentionPeriod=1, PubliclyAccessible=False, DBSubnetGroupName=subnet_group,
            Tags=_TAGS,
        )["DBInstance"]
        ctx.on_cleanup(lambda i=instance: _drop_instance(rds, i))
        assert created["DBInstanceStatus"] == "creating", (
            f"CreateDBInstance answered {created['DBInstanceStatus']!r}, expected 'creating'"
        )
        for op in list(pending):
            before = _status(rds, instance)
            if before != "creating":
                tried.append(f"{instance}: read {before!r} before {op}")
                break
            call, want_code, want_message = legs[op]
            want_message = want_message.format(i=instance)
            code, message = _outcome(lambda: call(instance))
            if (code, message) == (want_code, want_message):
                pending.remove(op)
                continue
            after = _status(rds, instance)
            assert after != "creating", (
                f"{op} on a creating instance answered {code!r} {message!r}; expected "
                f"{want_code!r} {want_message!r}"
            )
            assert code == _ACCEPTED, f"{op} answered {code!r} {message!r} once the instance was {after!r}"
            tried.append(f"{instance}: {op} accepted after the instance left creating ({after!r})")
            break
    assert not pending, (
        f"never observed the refusal of {pending} while creating in {_ATTEMPTS} instances: {tried!r}"
    )


def _password() -> str:
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(20)) + "9Aa"


def _outcome(fn) -> tuple[str, str | None]:
    """(code, message) of the refusal ``fn`` raises, or (_ACCEPTED, repr of the answer) when the
    target accepts the call."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return _ACCEPTED, repr(result)


def _status(rds, instance: str) -> str:
    return rds.describe_db_instances(DBInstanceIdentifier=instance)["DBInstances"][0]["DBInstanceStatus"]


def _snapshot(ctx, rds, instance: str) -> None:
    """CreateDBSnapshot, with the snapshot's delete registered first in case the target accepts it."""
    name = f"{instance}-snap"
    ctx.on_cleanup(lambda: _drop_snapshot(rds, name))
    rds.create_db_snapshot(DBSnapshotIdentifier=name, DBInstanceIdentifier=instance, Tags=_TAGS)


def _restore(ctx, rds, instance: str, subnet_group: str) -> None:
    """RestoreDBInstanceToPointInTime, with the target's delete registered first in case it is accepted."""
    target = f"{instance}-pitr"
    ctx.on_cleanup(lambda: _drop_instance(rds, target))
    rds.restore_db_instance_to_point_in_time(
        SourceDBInstanceIdentifier=instance, TargetDBInstanceIdentifier=target,
        UseLatestRestorableTime=True, DBInstanceClass="db.t3.micro", DBSubnetGroupName=subnet_group,
        Tags=_TAGS)


def _retry(fn, gone: str, busy: tuple[str, ...], timeout_s: float) -> None:
    """Run a delete, retrying while a ``busy`` code refuses it; ``gone`` counts as deleted."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == gone:
                return
            if code not in busy or time.monotonic() >= deadline:
                raise
        time.sleep(5)


def _drop_instance(rds, instance: str) -> None:
    """Delete the instance, retrying while its state refuses it, and wait until it is gone."""
    _retry(lambda: rds.delete_db_instance(DBInstanceIdentifier=instance, SkipFinalSnapshot=True,
                                          DeleteAutomatedBackups=True),
           "DBInstanceNotFound", ("InvalidDBInstanceState",), 1500.0)
    _gone(lambda: rds.describe_db_instances(DBInstanceIdentifier=instance), "DBInstanceNotFound",
          f"DB instance {instance}")


def _drop_snapshot(rds, name: str) -> None:
    _retry(lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=name),
           "DBSnapshotNotFound", ("InvalidDBSnapshotState",), 1500.0)


def _gone(describe, gone: str, what: str, timeout_s: float = 1500.0) -> None:
    """Poll ``describe`` until it raises ``gone``; a delete accepted while creating still lists it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            describe()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == gone:
                return
            raise
        if time.monotonic() >= deadline:
            raise RuntimeError(f"{what} still present {timeout_s:.0f}s after its delete")
        time.sleep(2)


def _subnet_group(ctx, rds) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-rds-dbsg-")
    rds.create_db_subnet_group(DBSubnetGroupName=name, DBSubnetGroupDescription="sim2real shared network",
                               SubnetIds=ctx.network().subnet_ids, Tags=_TAGS)
    ctx.on_cleanup(lambda: _retry(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name),
                                  "DBSubnetGroupNotFoundFault",
                                  ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"), 1500.0))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
