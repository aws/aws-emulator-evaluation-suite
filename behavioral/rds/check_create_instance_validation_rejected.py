"""create-instance-validation-rejected."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-instance-validation-rejected"
GROUP = 'errors'
SERVICES = ['rds']

ERR_INVALID_PARAMETER_VALUE = "InvalidParameterValue"
ERR_INVALID_PARAMETER_COMBINATION = "InvalidParameterCombination"
ERR_DB_INSTANCE_NOT_FOUND = "DBInstanceNotFound"
_RESERVED_USER = "rdsadmin"
_USER = "sim2real"
_PASS = "Sim2Real#Pass99"
_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


# ===== helpers (self-contained) =====


def _poll(fn, pred, *, timeout_s, interval_s=15):
    """Poll fn() until pred(value) or the deadline; returns the last value seen."""
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _instance(rds, inst_id):
    """DescribeDBInstances for one id, or None when it no longer exists."""
    try:
        return rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == ERR_DB_INSTANCE_NOT_FOUND:
            return None
        raise


def _delete_instance(rds, inst_id):
    """Best-effort teardown: delete an instance with no final snapshot."""
    try:
        rds.delete_db_instance(
            DBInstanceIdentifier=inst_id,
            SkipFinalSnapshot=True,
            DeleteAutomatedBackups=True,
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBInstanceNotFound":
            raise


def _client_error(fn):
    """Call fn(); return the ClientError it raised, or None if it returned normally."""
    try:
        fn()
    except ClientError as exc:
        return exc
    return None


def _default_engine_version(rds, engine):
    """The engine's current default version, or None when the catalog is unavailable."""
    try:
        versions = rds.describe_db_engine_versions(Engine=engine, DefaultOnly=True).get(
            "DBEngineVersions", []
        )
    except ClientError:
        return None
    return versions[0]["EngineVersion"] if versions else None
# ===== end helpers =====


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDBInstance refuses each distinct invalid-input class with its specific error code, HTTP
    400 and a message naming the violated constraint, and mints nothing; the identical request with
    every field legal is accepted.
    """
    rds = ctx.client("rds")
    version = _default_engine_version(rds, "postgres")

    def _base(inst_id):
        """A fully valid postgres CreateDBInstance request, used as the mutation baseline."""
        req = {
            "DBInstanceIdentifier": inst_id,
            "Engine": "postgres",
            "DBInstanceClass": "db.t3.micro",
            # StorageType is pinned: the AllocatedStorage minimum depends on the storage type,
            # not the engine. On AWS postgres accepts AllocatedStorage=5 on gp2 (gp2's minimum)
            # and refuses it on gp3 (whose minimum is 20). RDS defaults an unspecified
            # StorageType to gp2.
            "StorageType": "gp3",
            "AllocatedStorage": 20,
            "MasterUsername": _USER,
            "MasterUserPassword": _PASS,
            "BackupRetentionPeriod": 0,
            "DeletionProtection": False,
            "Tags": _MANAGED_TAGS,
            "DBSubnetGroupName": _network_db_subnet_group(ctx, rds),
        }
        if version:
            req["EngineVersion"] = version
        return req

    def _reject(label, expected_codes, *, message_must_contain=(), **mutation):
        """Break exactly one field, assert the specific refusal, assert nothing was minted."""
        inst_id = ctx.unique_name("sim2real-behav-bad-")
        req = _base(inst_id)
        req.update(mutation)
        exc = _client_error(lambda: rds.create_db_instance(**req))
        if exc is None:
            # Unexpected success: register teardown before failing so nothing leaks.
            ctx.on_cleanup(lambda: _delete_instance(rds, inst_id))
            raise AssertionError(
                f"{label}: CreateDBInstance was ACCEPTED; real RDS refuses this input "
                f"(mutation={mutation!r})"
            )
        code = exc.response.get("Error", {}).get("Code")
        assert code in expected_codes, (
            f"{label}: expected one of {sorted(expected_codes)}, got {code!r} "
            f"(message={exc.response.get('Error', {}).get('Message')!r})"
        )
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        assert status == 400, f"{label}: expected HTTP 400, got {status!r}"
        message = exc.response.get("Error", {}).get("Message") or ""
        for fragment in message_must_contain:
            assert fragment in message, (
                f"{label}: the refusal must name {fragment!r} -- that is what identifies WHICH "
                f"constraint was violated rather than just that something was wrong; got "
                f"{message!r}"
            )
        assert _instance(rds, inst_id) is None, (
            f"{label}: the refused CreateDBInstance still minted {inst_id}; a rejection must "
            "leave no resource behind"
        )

    # --- Reserved admin user name: 'rdsadmin' is the engine's own account on RDS.
    _reject(
        "reserved master username",
        {ERR_INVALID_PARAMETER_VALUE},
        MasterUsername=_RESERVED_USER,
    )

    # --- Admin password below the documented 8-character minimum.
    _reject(
        "master password below minimum length",
        {ERR_INVALID_PARAMETER_VALUE},
        MasterUserPassword="Sh0rt",
    )

    # --- Allocated storage below the minimum for the REQUESTED STORAGE TYPE. gp3 requires 20 GiB
    #     for postgres; the message names both the engine and the storage type, which is the
    #     evidence that the floor is storage-type-scoped rather than engine-wide. (The same
    #     AllocatedStorage=5 is legal on gp2 -- see the StorageType comment in _base.)
    _reject(
        "allocated storage below the gp3 minimum",
        {ERR_INVALID_PARAMETER_VALUE, ERR_INVALID_PARAMETER_COMBINATION},
        message_must_contain=("postgres", "gp3"),
        AllocatedStorage=5,
    )

    # --- A deprecated storage type. Magnetic ('standard') is still in the API surface and still
    #     modelled, but real RDS refuses to create on it; the refusal even names the replacements.
    #     Costs nothing.
    _reject(
        "deprecated magnetic storage type",
        {ERR_INVALID_PARAMETER_VALUE, ERR_INVALID_PARAMETER_COMBINATION},
        message_must_contain=("magnetic storage is deprecated",),
        StorageType="standard",
        AllocatedStorage=20,
    )

    # --- An instance class postgres does not offer (db.t2.micro is retired for postgres).
    _reject(
        "instance class not supported for engine",
        {ERR_INVALID_PARAMETER_VALUE, ERR_INVALID_PARAMETER_COMBINATION},
        message_must_contain=("db.t2.micro",),
        DBInstanceClass="db.t2.micro",
    )

    # --- Control case: every field legal -> accepted, and the record really appears.
    good_id = ctx.unique_name("sim2real-behav-inst-")
    resp = rds.create_db_instance(**_base(good_id))
    ctx.on_cleanup(lambda: _delete_instance(rds, good_id))
    assert resp["DBInstance"]["DBInstanceIdentifier"] == good_id
    assert resp["DBInstance"]["DBInstanceStatus"] in ("creating", "backing-up", "available"), (
        f"an accepted create must report a live status, got "
        f"{resp['DBInstance']['DBInstanceStatus']!r}"
    )
    assert resp["DBInstance"]["MasterUsername"] == _USER
    inst = _poll(lambda: _instance(rds, good_id), lambda i: i is not None, timeout_s=300, interval_s=10)
    assert inst is not None, (
        f"the accepted CreateDBInstance did not make {good_id} describable — the emulator "
        "rejects the invalid inputs but does not actually create the valid one"
    )
    assert inst["Engine"] == "postgres"
    assert inst["DBInstanceClass"] == "db.t3.micro"
    assert inst["AllocatedStorage"] == 20
    assert inst["StorageType"] == "gp3", (
        f"the accepted create asked for gp3, so the record must report gp3 (an unspecified "
        f"StorageType defaults to gp2, which is what made the below-minimum leg legal); got "
        f"{inst['StorageType']!r}"
    )


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
