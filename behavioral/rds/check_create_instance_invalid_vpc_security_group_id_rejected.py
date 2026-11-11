"""create-instance-invalid-vpc-security-group-id-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-instance-invalid-vpc-security-group-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["rds"]

_MASTER_USER = "sim2realadmin"
_MASTER_PASS = "Sim2RealPwd123"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """CreateDBInstance referencing a nonexistent VpcSecurityGroupId is rejected
    synchronously at creation time, not deferred to an instance that lands in a
    'failed' / 'incompatible-network' state."""
    rds = ctx.client("rds")
    bad_id = ctx.unique_name("sim2real-badsg-")
    bogus_sg = "sg-00000000000000bad"

    # Registered before the call, not after: if the target wrongly accepts the bogus security
    # group, _create_rejected raises immediately and a cleanup registered afterward would never
    # run, leaking the instance it just created.
    ctx.on_cleanup(lambda: _delete_instance(rds, bad_id))
    subnet_group = _network_db_subnet_group(ctx, rds)
    code, message = _create_rejected(
        lambda: rds.create_db_instance(
            DBInstanceIdentifier=bad_id,
            DBInstanceClass="db.t3.micro",
            Engine="postgres",
            MasterUsername=_MASTER_USER,
            MasterUserPassword=_MASTER_PASS,
            AllocatedStorage=20,
            VpcSecurityGroupIds=[bogus_sg],
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            DBSubnetGroupName=subnet_group,
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    # AWS's message carries a space before the first comma and an empty groupName.
    expected = f"Invalid security group , groupId= {bogus_sg}, groupName=."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no instance record was created at all -- not even a failed one.
    # Poll briefly: some accounts show a short eventual-consistency window before the
    # rejected identifier is fully absent from DescribeDBInstances.
    not_found = _wait_for_not_found(rds, bad_id, timeout_s=60)
    expected_nf = f"DBInstance {bad_id} not found."
    assert not_found.get("Message") == expected_nf, (
        f"expected message {expected_nf!r}, got {not_found.get('Message')!r}"
    )

    # Positive control: the same request without the bogus security group succeeds.
    good_id = ctx.unique_name("sim2real-goodsg-")
    rds.create_db_instance(
        DBInstanceIdentifier=good_id,
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername=_MASTER_USER,
        MasterUserPassword=_MASTER_PASS,
        AllocatedStorage=20,
        BackupRetentionPeriod=0,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, good_id))
    _wait_for_instance_status(rds, good_id, "available", timeout_s=900)


def _create_rejected(fn: Callable[[], Any]) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(
        f"expected CreateDBInstance to be rejected for the bogus VpcSecurityGroupId, "
        f"but it succeeded and returned {result!r}"
    )


def _wait_for_not_found(rds: Any, db_id: str, *, timeout_s: float) -> dict[str, str]:
    """Bounded poll until DescribeDBInstances refuses db_id with DBInstanceNotFound; return that
    refusal's Error dict."""
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        try:
            last = rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"]
        except ClientError as exc:
            last = exc.response["Error"]
            if last.get("Code") == "DBInstanceNotFound":
                return last
        time.sleep(5)
    raise AssertionError(
        f"instance {db_id!r} still not DBInstanceNotFound after {timeout_s}s; last describe: {last!r}"
    )


def _instance_status(rds: Any, db_id: str) -> str | None:
    try:
        return rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]["DBInstanceStatus"]
    except ClientError:
        return None



def _describe_instance(rds: Any, db_id: str) -> dict[str, Any]:
    return rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]


def _wait_for_instance_status(rds: Any, db_id: str, status: str, *, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        inst = _describe_instance(rds, db_id)
        if inst["DBInstanceStatus"] == status:
            return
        time.sleep(2)
    raise AssertionError(f"DB instance {db_id} never reached status={status!r} in {timeout_s}s")


def _delete_instance(rds: Any, db_id: str) -> None:
    try:
        rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("DBInstanceNotFound", "DBInstanceNotFoundFault"):
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
