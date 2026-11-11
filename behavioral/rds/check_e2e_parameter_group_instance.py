"""e2e-parameter-group-instance."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-parameter-group-instance"
GROUP = 'e2e_workflows'
SERVICES = ['rds']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Instance with custom parameter group — verifies association."""
    rds = ctx.client("rds")
    pg_name = ctx.unique_name("sim2real-behav-pg-")
    rds.create_db_parameter_group(
        DBParameterGroupName=pg_name,
        DBParameterGroupFamily="mysql8.0",
        Description="sim2real behavioral test parameter group",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=pg_name))
    rds.modify_db_parameter_group(
        DBParameterGroupName=pg_name,
        Parameters=[
            {
                "ParameterName": "max_connections",
                "ParameterValue": "200",
                "ApplyMethod": "pending-reboot",
            }
        ],
    )
    inst_id = ctx.unique_name("sim2real-behav-inst-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=inst_id,
        Engine="mysql",
        EngineVersion="8.0",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="sim2real",
        MasterUserPassword="Sim2Real#Pass99",
        BackupRetentionPeriod=0,
        DBParameterGroupName=pg_name,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: rds.delete_db_instance(
        DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True))
    # wait for available
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        status = rds.describe_db_instances(DBInstanceIdentifier=inst_id)[
            "DBInstances"
        ][0]["DBInstanceStatus"]
        if status == "available":
            break
        time.sleep(2)
    else:
        raise AssertionError(f"DB instance {inst_id} available not met in time")

    resp = rds.describe_db_instances(DBInstanceIdentifier=inst_id)
    pg_names = [
        pg["DBParameterGroupName"] for pg in resp["DBInstances"][0].get("DBParameterGroups", [])
    ]
    assert pg_name in pg_names, (
        f"expected custom parameter group {pg_name} attached to instance {inst_id}; "
        f"independent read reports {pg_names!r}"
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
