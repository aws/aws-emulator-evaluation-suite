"""concurrent-create-duplicate-instance."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError


from behavioral_harness import tags
import secrets

CHECK = "concurrent-create-duplicate-instance"
GROUP = 'instance_lifecycle'
SERVICES = ['rds']

def _wait_available(rds, inst_id, timeout_s=900) -> None:
    """Poll until a DB instance reaches 'available'."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = rds.describe_db_instances(DBInstanceIdentifier=inst_id)[
            "DBInstances"
        ][0]["DBInstanceStatus"]
        if status == "available":
            return
        time.sleep(2)
    raise AssertionError(f"DB instance {inst_id} available not met within {timeout_s}s")

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """N racers create the SAME DBInstanceIdentifier concurrently: exactly one
    wins and every loser rejects with DBInstanceAlreadyExists.
    """
    rds = ctx.client("rds")
    subnet_group = _network_db_subnet_group(ctx, rds)
    inst_id = ctx.unique_name("sim2real-behav-inst-race-")
    ctx.on_cleanup(lambda: rds.delete_db_instance(
        DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True))

    def create_once():
        try:
            rds.create_db_instance(
                DBInstanceIdentifier=inst_id,
                Engine="mysql",
                EngineVersion="8.0",
                DBInstanceClass="db.t3.micro",
                AllocatedStorage=20,
                MasterUsername="sim2real",
                MasterUserPassword="Aa1!" + secrets.token_urlsafe(18),
                BackupRetentionPeriod=0,
                Tags=[{"Key": "sim2real", "Value": "true"}],
                DBSubnetGroupName=subnet_group,
            )
            return None
        except ClientError as _e:
            return _e.response.get("Error", {}).get("Code"), _e.response.get("Error", {}).get("Message")

    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _: create_once(), range(3)))

    successes = [r for r in results if r is None]
    error_codes = [r for r in results if r is not None]
    assert len(successes) == 1, f"expected exactly 1 winner, got {len(successes)}"
    assert len(error_codes) == 2, f"expected 2 losers, got {len(error_codes)}"
    assert all(c == ("DBInstanceAlreadyExists", "DB instance already exists") for c in error_codes), error_codes

    # The instance may still be creating; wait so cleanup can safely delete it.
    _wait_available(rds, inst_id)


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
