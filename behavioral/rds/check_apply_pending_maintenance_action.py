"""apply-pending-maintenance-action."""
from __future__ import annotations

import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apply-pending-maintenance-action"
GROUP = 'maintenance'
SERVICES = ['rds']

ERR_RESOURCE_NOT_FOUND = "ResourceNotFoundFault"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ApplyPendingMaintenanceAction on a well-formed ARN for a nonexistent instance rejects with
    ResourceNotFoundFault, while the identical call on a real instance does not come back
    not-found."""
    rds = ctx.client("rds")
    account = ctx.client("sts").get_caller_identity()["Account"]

    instance_id = ctx.unique_name("sim2real-behav-inst-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        Engine="mysql",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="s2radmin",
        MasterUserPassword=_rand_password(),
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    )
    instance = _wait_instance_available(ctx, instance_id, timeout_s=1200)
    real_arn = instance["DBInstanceArn"]

    # The control may succeed or be refused for an unrelated reason (no pending action);
    # it only must not come back not-found.
    try:
        _apply(rds, real_arn)
        control_code = None
    except ClientError as e:
        control_code = e.response.get("Error", {}).get("Code")
    assert control_code != ERR_RESOURCE_NOT_FOUND, (
        f"positive control failed: apply_pending_maintenance_action against the real, "
        f"just-created instance {real_arn!r} returned {control_code!r} — the target may "
        f"be rejecting every call as {ERR_RESOURCE_NOT_FOUND!r} rather than specifically "
        f"detecting a nonexistent resource"
    )

    bogus_id = ctx.unique_name("sim2real-behav-inst-missing-")
    bogus_arn = f"arn:aws:rds:{ctx.region}:{account}:db:{bogus_id}"
    bogus_code, bogus_message = _apply_error(rds, bogus_arn)
    assert bogus_code == ERR_RESOURCE_NOT_FOUND, f"unexpected error code: {bogus_code!r}"
    expected = f"Resource not found: {bogus_id}"
    assert bogus_message == expected, f"unexpected message: {bogus_message!r} (expected {expected!r})"


def _apply(rds, resource_arn: str):
    return rds.apply_pending_maintenance_action(
        ResourceIdentifier=resource_arn,
        ApplyAction="system-update",
        OptInType="immediate",
    )


def _apply_error(rds, resource_arn: str) -> tuple[str, str]:
    try:
        _apply(rds, resource_arn)
    except ClientError as e:
        error = e.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(
        f"ApplyPendingMaintenanceAction on {resource_arn!r} succeeded; expected a rejection"
    )


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _wait_instance_available(ctx, instance_id: str, timeout_s: int = 1200, poll_s: int = 20):
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        if last["DBInstanceStatus"] == "available":
            return last
        time.sleep(poll_s)
    raise AssertionError(
        f"instance {instance_id} never became available within {timeout_s}s, "
        f"last status {last and last['DBInstanceStatus']!r}"
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
