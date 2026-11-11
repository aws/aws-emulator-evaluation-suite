"""read-replica-requires-source-backups."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "read-replica-requires-source-backups"
GROUP = "overly-permissive"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDBInstanceReadReplica from a source with BackupRetentionPeriod=0 is rejected with
    InvalidDBInstanceState and creates no replica, and succeeds from the same source once its backups
    are enabled."""
    rds = ctx.client("rds")
    instance_class = _instance_class(rds)

    primary_id = ctx.unique_name("sim2real-behav-rds-replnobak-")
    _create_instance(ctx, rds, primary_id, instance_class, BackupRetentionPeriod=0)
    _wait_instance_status(rds, primary_id, "available")
    assert _describe_instance(rds, primary_id)["BackupRetentionPeriod"] == 0, (
        "source instance must actually have automated backups disabled"
    )

    # Break leg: attempt a replica while the source's automated backups are disabled.
    replica_bad_id = ctx.unique_name("sim2real-behav-rds-replnobakrep-")
    # Track before attempting so an unexpectedly-successful replica still gets cleaned up.
    ctx.on_cleanup(lambda: _delete_instance(rds, replica_bad_id))
    code, message = _error(
        lambda: rds.create_db_instance_read_replica(
            DBInstanceIdentifier=replica_bad_id,
            SourceDBInstanceIdentifier=primary_id,
            DBInstanceClass=instance_class,
            Tags=[{"Key": "sim2real", "Value": "true"}],
        )
    )
    assert code == "InvalidDBInstanceState", f"expected InvalidDBInstanceState, got {code!r}"
    expected = (
        "Automated backups are not enabled for this database instance. To enable automated "
        "backups, use ModifyDBInstance to set the backup retention period to a non-zero value."
    )
    assert message == expected, f"unexpected error message: {message!r} != {expected!r}"
    assert _describe_instance_or_none(rds, replica_bad_id) is None, (
        "no replica instance should exist after a rejected create-read-replica call"
    )

    # Restore: re-enable automated backups on the SAME source and wait for it to actually apply.
    rds.modify_db_instance(
        DBInstanceIdentifier=primary_id, BackupRetentionPeriod=1, ApplyImmediately=True
    )
    _wait_backup_retention(rds, primary_id, 1)

    # Positive control: the identical call against the now-eligible source must succeed — this
    # is what distinguishes "rejects a source with backups disabled" from "rejects every
    # CreateDBInstanceReadReplica call in this account".
    replica_good_id = ctx.unique_name("sim2real-behav-rds-replnobakok-")
    ctx.on_cleanup(lambda: _delete_instance(rds, replica_good_id))
    rds.create_db_instance_read_replica(
        DBInstanceIdentifier=replica_good_id,
        SourceDBInstanceIdentifier=primary_id,
        DBInstanceClass=instance_class,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    replica = _wait_instance_status(rds, replica_good_id, "available")
    assert replica["ReadReplicaSourceDBInstanceIdentifier"] == primary_id, (
        f"expected replica sourced from {primary_id!r}, "
        f"got {replica.get('ReadReplicaSourceDBInstanceIdentifier')!r}"
    )


# RDS control-plane operations are slow: a fresh DB instance typically needs 5-12
# minutes to reach `available`, so timeouts must be generous or the check fails
# spuriously.
_DEFAULT_TIMEOUT = 2400
_DEFAULT_INTERVAL = 15


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an over-permissive target accepting a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=_DEFAULT_TIMEOUT, interval_s=_DEFAULT_INTERVAL,
                description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _resolve_engine(rds) -> tuple[str, str]:
    """The default postgres engine version + its parameter-group family.

    Hardcoding an engine version rots: old major versions reach end-of-life and
    start getting rejected. Resolve it from the live API instead.
    """
    versions = rds.describe_db_engine_versions(Engine="postgres", DefaultOnly=True).get(
        "DBEngineVersions", []
    )
    if not versions:
        raise AssertionError("no default postgres engine version available")
    return versions[0]["EngineVersion"], versions[0]["DBParameterGroupFamily"]


def _instance_class(rds) -> str:
    """Smallest orderable burstable class for the resolved engine version."""
    version, _family = _resolve_engine(rds)
    classes: set[str] = set()
    paginator = rds.get_paginator("describe_orderable_db_instance_options")
    for page in paginator.paginate(Engine="postgres", EngineVersion=version):
        for opt in page.get("OrderableDBInstanceOptions", []):
            classes.add(opt["DBInstanceClass"])
    for preferred in ("db.t4g.micro", "db.t3.micro", "db.t4g.small", "db.t3.small"):
        if preferred in classes:
            return preferred
    if not classes:
        raise AssertionError(f"no orderable instance classes for postgres {version}")
    return sorted(classes)[0]


def _describe_instance(rds, db_instance_id: str) -> dict:
    return rds.describe_db_instances(DBInstanceIdentifier=db_instance_id)["DBInstances"][0]


def _describe_instance_or_none(rds, db_instance_id: str) -> dict | None:
    try:
        return _describe_instance(rds, db_instance_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "DBInstanceNotFound":
            return None
        raise


def _wait_instance_status(rds, db_instance_id: str, target_status: str,
                          timeout_s: int = _DEFAULT_TIMEOUT, interval_s: int = _DEFAULT_INTERVAL) -> dict:
    _poll_until(
        lambda: _describe_instance(rds, db_instance_id)["DBInstanceStatus"],
        lambda status: status == target_status,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"instance {db_instance_id} to reach {target_status!r}",
    )
    return _describe_instance(rds, db_instance_id)


def _wait_backup_retention(rds, db_instance_id: str, target: int,
                           timeout_s: int = _DEFAULT_TIMEOUT, interval_s: int = _DEFAULT_INTERVAL) -> dict:
    return _poll_until(
        lambda: _describe_instance(rds, db_instance_id),
        lambda inst: inst["DBInstanceStatus"] == "available"
        and inst["BackupRetentionPeriod"] == target,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"instance {db_instance_id} backup retention to reach {target!r} while available",
    )


def _delete_instance(rds, db_instance_id: str) -> None:
    """Best-effort teardown.

    DeleteAutomatedBackups=True matters: without it, an instance that had
    BackupRetentionPeriod > 0 leaves retained automated backups behind after
    deletion, which linger as billable/indexed resources.
    """
    try:
        rds.modify_db_instance(DBInstanceIdentifier=db_instance_id, DeletionProtection=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "AuthorizationNotFound",
            "BackupPolicyNotFoundFault",
            "CertificateNotFound",
            "DBInstanceNotFound",
            "DBParameterGroupNotFound",
            "DBSecurityGroupNotFound",
            "DBSubnetGroupNotFoundFault",
            "DomainNotFoundFault",
            "OptionGroupNotFoundFault",
        ):
            raise
    try:
        rds.delete_db_instance(
            DBInstanceIdentifier=db_instance_id,
            SkipFinalSnapshot=True,
            DeleteAutomatedBackups=True,
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBInstanceNotFound":
            raise


def _create_instance(ctx, rds, db_instance_id: str, instance_class: str, **overrides) -> dict:
    version, _family = _resolve_engine(rds)
    params = dict(
        DBInstanceIdentifier=db_instance_id,
        DBInstanceClass=instance_class,
        Engine="postgres",
        EngineVersion=version,
        MasterUsername="dbadmin",
        MasterUserPassword="SuperSecret123!",
        AllocatedStorage=20,
        BackupRetentionPeriod=1,
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    params.update(overrides)
    ctx.on_cleanup(lambda: _delete_instance(rds, db_instance_id))
    return rds.create_db_instance(**params)["DBInstance"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
