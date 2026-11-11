"""create-instance-nonexistent-option-group-rejected."""
from __future__ import annotations

import time

import random
import string

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-instance-nonexistent-option-group-rejected"
GROUP = "overly-permissive"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDBInstance referencing a nonexistent OptionGroupName is rejected synchronously
    (no instance is provisioned), rather than silently falling back to the default option group.
    """
    rds = ctx.client("rds")
    bad_instance_id = ctx.unique_name("sim2real-rds-badopt-")
    password = _rds_password()
    bogus_option_group = "sim2real-does-not-exist-option-group"

    # Safety net: if the create is wrongly accepted, the instance is still deleted; not-found
    # when the rejection behaves correctly.
    ctx.on_cleanup(lambda: _delete_instance(rds, bad_instance_id))

    subnet_group = _network_db_subnet_group(ctx, rds)
    code, message = _error_code(
        lambda: rds.create_db_instance(
            DBInstanceIdentifier=bad_instance_id,
            DBInstanceClass="db.t3.micro",
            Engine="mysql",
            MasterUsername="sim2real",
            MasterUserPassword=password,
            AllocatedStorage=20,
            OptionGroupName=bogus_option_group,
            Tags=[{"Key": "sim2real", "Value": "true"}],
            DBSubnetGroupName=subnet_group,
        )
    )
    assert code == "OptionGroupNotFoundFault", f"expected OptionGroupNotFoundFault, got {code}"
    expected = f"Specified OptionGroupName: {bogus_option_group} not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: no instance was ever created under this identifier
    nf_code, nf_message = _error_code(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=bad_instance_id)
    )
    assert nf_code == "DBInstanceNotFound", f"expected DBInstanceNotFound, got {nf_code}"
    expected_nf = f"DBInstance {bad_instance_id} not found."
    assert nf_message == expected_nf, f"expected message {expected_nf!r}, got {nf_message!r}"

    # --- positive control: creating with a *valid* option group succeeds ---
    # A pre-existing "default:mysql-..." option group is not guaranteed to be discoverable via
    # DescribeOptionGroups: AWS materializes it lazily, only after this account has actually used
    # the engine, so a fresh account reports none. Create a real option group explicitly instead
    # of depending on that history.
    _, major_engine_version = _mysql_engine_version(rds)
    valid_option_group = ctx.unique_name("sim2real-rds-optgrp-")
    rds.create_option_group(
        OptionGroupName=valid_option_group,
        EngineName="mysql",
        MajorEngineVersion=major_engine_version,
        OptionGroupDescription="sim2real positive control for create-instance-nonexistent-option-group-rejected",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_option_group(rds, valid_option_group))

    good_instance_id = ctx.unique_name("sim2real-rds-goodopt-")
    rds.create_db_instance(
        DBInstanceIdentifier=good_instance_id,
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="sim2real",
        MasterUserPassword=password,
        AllocatedStorage=20,
        OptionGroupName=valid_option_group,
        BackupRetentionPeriod=0,
        MultiAZ=False,
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        DBSubnetGroupName=subnet_group,
    )
    # Delete immediately rather than waiting for "available": the 60s ctx.on_cleanup budget cannot
    # fit RDS's multi-minute provisioning time, and RDS accepts DeleteDBInstance mid-creation.
    ctx.on_cleanup(lambda: _delete_instance(rds, good_instance_id))

    created = rds.describe_db_instances(DBInstanceIdentifier=good_instance_id)["DBInstances"][0]
    assert created["DBInstanceStatus"] in ("creating", "backing-up", "available"), (
        f"expected a healthy post-create status, got {created['DBInstanceStatus']!r}"
    )
    option_names = {m["OptionGroupName"] for m in created["OptionGroupMemberships"]}
    assert valid_option_group in option_names, "positive-control instance did not use the requested option group"


# ===== helpers =====
def _rds_password() -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=24)) + "9Aa"


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, so accepting
    input AWS refuses can never match an expected error code."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


def _delete_instance(rds, instance_id: str) -> None:
    _delete_when_released(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True),
        ("InvalidDBInstanceState",),
        ("DBInstanceNotFound",),
        timeout_s=300.0,
        interval_s=2.0,
    )


def _mysql_engine_version(rds) -> tuple[str, str]:
    """A real, orderable mysql (EngineVersion, MajorEngineVersion) pair."""
    versions = rds.describe_db_engine_versions(Engine="mysql", DefaultOnly=True).get("DBEngineVersions", [])
    if not versions:
        versions = rds.describe_db_engine_versions(Engine="mysql").get("DBEngineVersions", [])
    if not versions:
        raise AssertionError("no orderable mysql engine version found")
    v = versions[0]
    return v["EngineVersion"], v["MajorEngineVersion"]


def _delete_option_group(rds, option_group_name: str) -> None:
    """The option group is refused while the deleting instance still uses it."""
    _delete_when_released(
        lambda: rds.delete_option_group(OptionGroupName=option_group_name),
        ("InvalidOptionGroupStateFault",),
        ("OptionGroupNotFoundFault",),
        timeout_s=1200.0,
        interval_s=2.0,
    )


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
    """Delete, retrying while a resource that is being deleted still uses it; other errors raise."""
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
